import time
import logging
import os
import errno
import datetime
import hashlib
import sys
import pathlib
from random import Random
from typing import Any

from .proto import Protocol, Message, MessageParsingError
from .publisher import Publisher, PublisherOperationError
from .agent import AgentMultiplexer, Agent, AgentError
from .encoder import Encoder, EncodingError
from .decoder import Decoder, DecodingError
from .mutator import Mutation, MutatorCompleted
from .utils.graph import Path
from .utils.errs import FuzzyDooError


class FuzzingEngineError(FuzzyDooError):
    """Generic error for the `Engine` class."""


class UnrecoverableAgentError(FuzzingEngineError):
    """Exception raised when an unrecoverable error occurs."""


class TestCaseExecutionError(FuzzingEngineError):
    """Exception raised when an error occurs during test case execution."""


class TestCaseSetupError(FuzzingEngineError):
    """Exception raised when an error occurs during test case setup."""


class Engine:
    """The `Engine` class is the main component of the FuzzyDoo fuzzing framework. It orchestrates
    the entire fuzzing process, including protocol fuzzing, message mutation, encoding, decoding,
    monitoring, and result handling.

    The `Engine` class is responsible for managing the fuzzing process. It initializes the
    necessary components, such as protocols to be fuzzed, message sources, target systems,
    agents, encoders, decoders, and result storage. It also provides methods to start the fuzzing
    process, calculate runtime and execution speed, and handle target system restarts.

    Attributes:
        main_seed: Seed value for randomization.
        protocols: List of protocols to be fuzzed.
        source: Source of messages that will be fuzzed.
        target: Target system to which the mutated messages will be forwarded.
        agent: Agent multiplexer containing all the agents to use during the testing process.
        encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
        decoders: List of decoders to decode the data received by `source` and prepare them to
            be fuzzed.
        findings_dir_path: Path to the directory where findings will be stored.
        max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
        stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a
            vulnerability.
        wait_time_before_test_end: Time to wait before terminating a single test in case no message
            is received by `source` or by `target` (in seconds).
        target_restart_timeout: Time to wait after restarting the target system and before
            checking for its liveness (in seconds).


    Todo: add an example once everything is done properly.
    """

    def __init__(self,
                 main_seed: int,
                 protocol: Protocol,
                 source: Publisher,
                 target: Publisher,
                 agents: list[Agent],
                 encoders: list[Encoder],
                 decoders: list[Decoder],
                 findings_dir_path: pathlib.Path,
                 max_attempts_of_target_restart: int,
                 max_test_cases_per_epoch: int,
                 stop_on_find: bool,
                 wait_time_before_test_end: int,
                 target_restart_timeout: int):
        """Initialize the `Engine` class with the provided parameters.

        The `Engine` class orchestrates the fuzzing process, managing protocols, message sources,
        target systems, monitors, encoders, decoders, findings directory, and other parameters.

        Parameters:
            main_seed: Seed value for randomization.
            protocol: Protocol to be fuzzed.
            source: Source of messages that will be fuzzed.
            target: Target system to which the mutated messages will be forwarded.
            agents: List of agents to use during the testing process.
            encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
            decoders: List of decoders to decode the data received by `source` and prepare them to
                be fuzzed.
            findings_dir_path: Path to the directory where findings will be stored.
            max_attempts_of_target_restart: Maximum number of attempts to restart the target system.
            max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
            stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a
                vulnerability.
            wait_time_before_test_end: Time to wait before terminating a single test in case no
                message is received by `source` or by `target` (in seconds).
            target_restart_timeout: Time to wait after restarting the target system and before
                checking for its liveness (in seconds).
        """

        self.main_seed: int = main_seed
        self.protocol: Protocol = protocol
        self.source: Publisher = source
        self.target: Publisher = target
        self.encoders: list[Encoder] = encoders
        self.decoders: list[Decoder] = decoders

        self.agent: AgentMultiplexer = AgentMultiplexer()
        for a in agents:
            self.agent.add_agent(a)

        self.findings_dir_path: pathlib.Path | None = findings_dir_path
        self.max_attempts_of_target_restart: int = max_attempts_of_target_restart
        self.max_test_cases_per_epoch: int = max_test_cases_per_epoch
        self.stop_on_find: bool = stop_on_find
        self.wait_time_before_test_end: int = wait_time_before_test_end
        self.target_restart_timeout: int = target_restart_timeout

        self.start_time: float = time.time()
        self.end_time: float | None = None

        self._logger: logging.Logger = logging.getLogger('engine')

        if not self.findings_dir_path.exists():
            try:
                os.mkdir(self.findings_dir_path)
            except OSError as err:
                if err.errno != errno.EEXIST:
                    self._logger.error("Could not create findings directory %s: %s",
                                       self.findings_dir_path, err)
            else:
                self._logger.info("Created findings directory %s",
                                  self.findings_dir_path)

        self._current_epoch: int | None = None
        """Current epoch in the fuzzing process."""

        self._epoch_cases_fuzzed: int | None = None
        """Number of test cases fuzzed in the current epoch."""

        self._epoch_stop: bool = False
        """Flag indicating whether the current epoch has been stopped."""

        self._epoch_stop_reason: str | None = None
        """Reason why the current epoch stopped."""

        self._num_cases_actually_fuzzed: int = 0
        """Number of test cases actually fuzzed during the current run."""

        self._run_id: str | None = None
        """Unique identifier for the current fuzzing run."""

        self._run_path: pathlib.Path | None = None
        """Path to the directory where findings relative to the current run will be stored."""

        self._epoch_seed: int | None = None
        """Seed value for the current epoch."""

        self._epoch_random: Random | None = None
        """Random number generator used inside the current epoch."""

        self._epoch_mutations: list[tuple[Mutation, str]] = []
        """List of mutations to perform during the current epoch and the associated fuzzable path."""

        self._test_case_stop_reason: str | None = None
        """Reason why the current test case stopped."""

    @property
    def runtime(self) -> float:
        """Calculate the total runtime of the fuzzing engine.

        Returns:
            float: The total runtime of the fuzzing engine in seconds.
        """

        if self.end_time is not None:
            t = self.end_time
        else:
            t = time.time()
        return t - self.start_time

    @property
    def exec_speed(self) -> float:
        """Calculate the execution speed of the fuzzing engine.

        The execution speed is calculated by dividing the number of cases
        actually fuzzed by the total runtime of the fuzzing engine.

        Returns:
            float: The execution speed of the fuzzing engine in cases per second.
        """

        return self._num_cases_actually_fuzzed / self.runtime

    def run(self) -> bool:
        """Start to fuzz the protocol specified.

        Returns:
            bool: `True` if the protocol is successfully fuzzed, `False` otherwise.
        """

        # create the findings directory for the current run
        self._run_id = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0).isoformat().replace(":", "-")
        self._run_path = self.findings_dir_path / pathlib.Path(self._run_id)
        if not self._run_path.exists():
            try:
                os.mkdir(self._run_path)
            except OSError as err:
                if err.errno != errno.EEXIST:
                    self._logger.error(
                        "Could not create directory %s: %s", self._run_path, err)
                    return 0
            else:
                self._logger.debug(
                    "Created current run findings directory %s", self._run_path)

        self.start_time = time.time()
        self._num_cases_actually_fuzzed = 0

        result = self._fuzz_protocol()

        self.agent.on_shutdown()

        self.end_time = time.time()
        return result

    def _fuzz_protocol(self) -> bool:
        """Fuzz all the possible routes for the current protocol.

        This function iterates over all the possible paths in the current protocol and fuzzes each
        path using the `fuzz_epoch` method.

        Returns:
            bool: `True` if all the paths were successfully fuzzed without errors, `False`
                otherwise.
        """

        self._current_epoch = 0
        self._logger.info("Fuzzing of protocol %s started", self.protocol.name)

        res = True
        epoch_seed_generator = Random(
            hashlib.sha512(self.main_seed.to_bytes()).digest())
        for path in self.protocol:
            epoch_seed = epoch_seed_generator.randint(0, sys.maxsize * 2 + 1)
            res = self.fuzz_epoch(path, epoch_seed)
            if not res:
                break

        self._logger.info("Fuzzing of protocol %s ended", self.protocol.name)
        self._current_epoch = None

        return res

    def fuzz_epoch(self, path: Path, seed: int) -> bool:
        """Fuzz a single epoch on the given path.

        Args:
            path: Path in the protocol to be fuzzed.
            seed: Seed value for the current epoch.

        Returns:
            bool: `True` if the epoch is completed without errors, `False` otherwise.
        """

        if self._current_epoch is not None:
            self._current_epoch += 1
            self._logger.info("Epoch #%s started", self._current_epoch)
        else:
            self._logger.info("Starting epoch with seed %s", seed)

        self._epoch_seed = seed

        # first we generate the mutations only
        try:
            self._fuzz_single_epoch(path, generate_only=True)
        except FuzzingEngineError as e:
            if self._current_epoch is None:
                self.agent.on_shutdown()
            self._logger.error(
                "Error while generating the mutations: %s", str(e))
            return False

        # then we apply the mutations
        try:
            self._fuzz_single_epoch(path)
        except FuzzingEngineError as e:
            if self._current_epoch is None:
                self.agent.on_shutdown()
            self._logger.error("Error while executing the epoch: %s", str(e))
            return False

        if self._current_epoch is not None:
            self._logger.info("Epoch #%s terminated for reason: %s",
                              self._current_epoch, self._epoch_stop_reason)
        else:
            self.agent.on_shutdown()
            self._logger.info("Epoch terminated for reason: %s",
                              self._epoch_stop_reason)

        return True

    def _fuzz_single_epoch(self, path: Path, generate_only: bool = False):
        """Fuzz a single epoch for the current protocol.

        Parameters:
            path: Path in the protocol to be fuzzed.
            generate_only: A flag indicating whether mutations should be only generated and not
            applied.

        Raises:
            UnrecoverableAgentError: If any unrecoverable error occurs.
            TestCaseExecutionError: If at least one test case was not completed due to an execution
                error.
        """

        if generate_only:
            self._logger.info(
                "Generating mutations for epoch #%s", self._current_epoch)

        self._logger.debug("Current seed: %s", self._epoch_seed)
        self._epoch_random = Random(hashlib.sha512(
            self._epoch_seed.to_bytes()).digest())

        # if we have only to generate mutations, run a single test case with `generate_only=True`
        if generate_only:
            self._fuzz_single_test_case(path, None, True)

            self._logger.info("Generated %s mutations",
                              len(self._epoch_mutations))
            return

        self._epoch_stop = False
        self._epoch_stop_reason = None
        self._epoch_cases_fuzzed = 0

        # otherwise, run a test case for each mutation
        for mutation in self._epoch_mutations:
            self._fuzz_single_test_case(path, mutation)
            if self._epoch_stop:
                self._epoch_stop_reason = self._test_case_stop_reason
                break
        else:
            self._epoch_stop_reason = "Exhausted all test cases"

    def _test_case_setup(self, part_of_epoch: bool):
        """Prepare everything for the execution of a test case.

        Arguments:
            part_of_epoch: Whether the test case is part of an epoch or not.

        Raises:
            TestCaseSetupError: If the test setup was not completed.
        """

        self._test_case_stop_reason = None

        for enc in self.encoders:
            enc.reset()

        for dec in self.decoders:
            dec.reset()

        self.source.start()
        if not self.source.started:
            self._logger.debug("Failed to start the source publisher")
            raise TestCaseSetupError("failed to start the source publisher")

        self.target.start()
        if not self.target.started:
            self._logger.debug("Failed to start the target publisher")
            raise TestCaseSetupError("failed to start the target publisher")

        if part_of_epoch:
            self._logger.info("Test case #%s started",
                              self._epoch_cases_fuzzed+1)
        else:
            self._logger.info("Test case started")

    def _test_case_teardown(self, test_completed: bool, part_of_epoch: bool):
        """Do everything that is necessary to clean up after the execution of a test case.

        Arguments:
            test_completed: Whether the test case completed successfully.
            part_of_epoch: Whether the test case is part of an epoch or not.
        """

        if self.source.started:
            self.source.stop()

        if self.target.started:
            self.target.stop()

        if part_of_epoch:
            if test_completed:
                self._num_cases_actually_fuzzed += 1

            self._epoch_cases_fuzzed += 1
            self._logger.info("Test case #%s stopped",
                              self._epoch_cases_fuzzed)
        else:
            self._logger.info("Test case stopped")

    def _fuzz_single_test_case(self, path: Path, mutation: tuple[Mutation, str] | None, generate_only: bool = False):
        """Fuzz a given test case from a given path.

        Args:
            path: Path in the protocol to be fuzzed.
            mutation: Mutation to use, or None if no mutation should be used.
            generate_only: A flag indicating whether mutations should be only generated and not
                applied.

        Raises:
            UnrecoverableAgentError: If any unrecoverable error occurs.
            TestCaseExecutionError: If the test case was not completed due to an execution error.
        """

        part_of_epoch = self._epoch_cases_fuzzed is not None

        try:
            self.agent.on_test_start(str(path))
            self._test_case_setup(part_of_epoch)
        except AgentError as e:
            self._test_case_teardown(False, part_of_epoch)
            raise UnrecoverableAgentError(str(e)) from e
        except TestCaseSetupError as e:
            self._test_case_teardown(False, part_of_epoch)
            raise TestCaseExecutionError(str(e)) from e

        timestamp_last_message_sent = time.time()
        test_case_stop = False
        path = iter(path)
        msg = None
        while not test_case_stop:
            from_target = False

            # receive some data or test if we reached some threshold
            try:
                if self.target.data_available():
                    self._logger.debug(
                        "Data available from publisher %s", type(self.target))
                    from_target = True
                    data = self.source.receive()
                elif self.source.data_available():
                    self._logger.debug(
                        "Data available from publisher %s", type(self.source))
                    msg = next(path)
                    data = self.source.receive()
                else:
                    delta = time.time() - timestamp_last_message_sent
                    self._logger.debug(
                        "Delta time since last sent message: %.4fs", delta)
                    if delta >= self.wait_time_before_test_end:
                        self._logger.debug(
                            "Timeout reached (threshold: %.4fs)", self.wait_time_before_test_end)
                        test_case_stop = True
                        self._test_case_stop_reason = "Timeout"
                    continue
            except PublisherOperationError as e:
                self._logger.debug("Error while receiving message: %s", str(e))
                self._test_case_teardown(False, part_of_epoch)
                raise TestCaseExecutionError(
                    "message receiving error: " + str(e)) from e

            to_be_fuzzed = msg == path.path[-1].dst
            self._logger.debug("Data received %s", data)
            self._logger.debug("To be fuzzed: %s", to_be_fuzzed)

            # try to apply all the decoding steps, this even if the message is from the target
            # becuase maybe it contains some info needed to decode future messages
            original_data = data
            try:
                for dec in self.decoders:
                    self._logger.debug(
                        "Decoding message with decoder %s", type(dec))
                    self._logger.debug("Message: %s", data)
                    data = dec.decode(data, self.protocol,
                                      msg, to_be_fuzzed)
            except DecodingError as e:
                self._logger.debug("Error while decoding message: %s", str(e))
                self._test_case_teardown(False, part_of_epoch)
                raise TestCaseExecutionError(
                    "message decoding error: " + str(e)) from e

            self._logger.debug("Decoded data %s", data)

            # if the message was from the target, send it to the source
            if from_target:
                try:
                    self._logger.debug(
                        "Sending message with publisher %s", type(self.source))
                    self.source.send(original_data)
                except PublisherOperationError as e:
                    self._logger.debug(
                        "Error while sending message: %s", str(e))
                    self._test_case_teardown(False, part_of_epoch)
                    raise TestCaseExecutionError(
                        "message sending error: " + str(e)) from e

                timestamp_last_message_sent = time.time()
                continue

            # from now on, the message is assumed to be from the source

            # try to parse the message even if it is not the one that has to be fuzzed to ensure
            # our path is the correct one.
            try:
                self._logger.debug("Parsing message with parser %s", type(msg))
                msg.parse(data)
            except MessageParsingError as e:
                self._logger.debug("Error while parsing message: %s", str(e))
                self._test_case_teardown(False, part_of_epoch)
                raise TestCaseExecutionError(
                    "message parsing error: " + str(e)) from e

            # if it is the one that has to be fuzzed, fuzz it
            if to_be_fuzzed:
                # if the flag is set, generate mutations and stop the fuzzing process
                if generate_only:
                    self._logger.debug("Generating mutations")
                    self._epoch_mutations = self._generate_mutations(msg)
                    self._epoch_stop = test_case_stop = True
                    self._test_case_stop_reason = "Generation completed"
                    continue

                self._logger.debug("Applying mutation")
                mutated_data = mutation[0].apply(
                    msg.get_content_by_path(mutation[1]))
                msg.set_content_by_path(mutation[1], mutated_data)
                data = msg.raw()
                self._logger.debug("Mutated data %s", data)

            try:
                for enc in self.encoders:
                    self._logger.debug(
                        "Encoding message with encoder %s", type(enc))
                    self._logger.debug("Message: %s", data)
                    data = enc.encode(data, self.protocol, msg)
            except EncodingError as e:
                self._logger.debug("Error while encoding message: %s", str(e))
                self._test_case_teardown(False, part_of_epoch)
                raise TestCaseExecutionError(
                    "message encoding error: " + str(e)) from e

            self._logger.debug("Encoded data %s", data)

            try:
                self._logger.debug(
                    "Sending message with publisher %s", type(self.target))
                self.target.send(data)
            except PublisherOperationError as e:
                self._logger.debug("Error while sending message: %s", str(e))
                self._test_case_teardown(False, part_of_epoch)
                raise TestCaseExecutionError(
                    "message sending error: " + str(e)) from e
            else:
                timestamp_last_message_sent = time.time()

            test_case_stop = not to_be_fuzzed

            try:
                if self.agent.redo_test():
                    return self._fuzz_single_test_case(path, mutation, generate_only)

                if self.agent.fault_detected():
                    self._logger.info("Fault detected")
                    self._test_case_stop_reason = "Fault detected"

                    data = self.agent.get_data()

                    # TODO: write the data somewhere

                    if part_of_epoch and self.stop_on_find:
                        self._epoch_stop = True

                    self._logger.debug("Stopping epoch: %s", self._epoch_stop)
                else:
                    self._test_case_stop_reason = "Test case completed"
            except AgentError as e:
                self._test_case_teardown(False, part_of_epoch)
                raise UnrecoverableAgentError(str(e)) from e

        self._test_case_teardown(True, part_of_epoch)

        try:
            self.agent.on_test_end()
        except AgentError as e:
            raise UnrecoverableAgentError(str(e)) from e

    def _generate_mutations(self, data: Message) -> list[tuple[Mutation, str]]:
        """Generates a list of mutations for the given data.

        Parameters:
            data: The data for which mutations need to be generated.

        Returns:
            list[tuple[Mutation, str]]: A list of mutations generated for the given data.
        """

        # instantiate all the mutators with a seed
        mutators = []
        for mutator in data.mutators():
            mutator_seed = self._epoch_random.randint(0, sys.maxsize * 2 + 1)
            m = mutator(seed=mutator_seed)
            mutators.append(m)

        # generate the mutations
        mutations = []
        while True:
            mutator, fuzzable_path = self._epoch_random.choice(mutators)
            mutation = mutator.mutate(data.get_content_by_path(fuzzable_path))
            if mutation not in mutations:
                mutations.append((mutation, fuzzable_path))

            # if the mutator used is exhausted then remove it from the list of mutators
            try:
                mutator.next()
            except MutatorCompleted:
                mutators.remove(mutator)

            if len(mutators) == 0 or len(mutations) >= self.max_test_cases_per_epoch:
                break

        return mutations

    def fuzz_test_case(self, path: Path, mutation_type: str, mutator_state: Any, mutated_field: str, mutated_entity_qualified_name: str):
        """Fuzz a given test case from a given path.

        Args:
            path: Path in the protocol to be fuzzed.
            mutation_type: Type of mutation to be applied.
            mutator_state: State of the mutator to be used.
            mutated_field: The name of the field in the `Fuzzable` object that was mutated.
            mutated_entity_qualified_name: The qualified name of the `Fuzzable` object that was 
                mutated.
        """

        # pylint: disable=import-outside-toplevel
        from pydoc import locate
        mutation = (Mutation(locate(mutation_type),
                             mutator_state,
                             mutated_field),
                    mutated_entity_qualified_name)

        try:
            self._fuzz_single_test_case(path, mutation)
        except FuzzingEngineError as e:
            self._logger.error(str(e))

        self.agent.on_shutdown()


__all__ = ['Engine']
