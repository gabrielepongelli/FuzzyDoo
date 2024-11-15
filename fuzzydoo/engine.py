import time
import logging
import os
import datetime
import hashlib
import sys
import pathlib
from random import Random
from typing import Any

from fuzzydoo.proto.protocol import ProtocolPath

from .proto import Protocol, Message, MessageParsingError
from .publisher import Publisher, PublisherOperationError
from .agent import AgentMultiplexer, Agent, AgentError, ExecutionContext
from .encoder import Encoder, EncodingError
from .decoder import Decoder, DecodingError
from .mutator import Mutation, Mutator, MutatorCompleted
from .utils.graph import Path
from .utils.errs import FuzzyDooError


class FuzzingEngineError(FuzzyDooError):
    """Generic error for the `Engine` class."""


class TestCaseExecutionError(FuzzingEngineError):
    """Exception raised when an error occurs during test case execution."""


class TimeoutExecutionError(FuzzingEngineError):
    """Exception raised when a timeout limit is reached during the execution."""


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
        protocol: Protocol to be fuzzed.
        actor: Name of the actor in the protocol to act as.
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
                 actor: str,
                 actors: dict[str, Publisher],
                 agents: list[Agent],
                 encoders: list[Encoder],
                 decoders: list[Decoder],
                 findings_dir_path: pathlib.Path,
                 max_attempts_of_test_redo: int,
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
            actor: Name of the actor in the protocol to act as.
            source: Source of messages that will be fuzzed.
            target: Target system to which the mutated messages will be forwarded.
            agents: List of agents to use during the testing process.
            encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
            decoders: List of decoders to decode the data received by `source` and prepare them to
                be fuzzed.
            findings_dir_path: Path to the directory where findings will be stored.
            max_attempts_of_test_redo: Maximum number of attempts to re perform a test case.
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
        self.actor: str = actor
        self.actors: dict[str, Publisher] = actors
        self.encoders: list[Encoder] = encoders
        self.decoders: list[Decoder] = decoders

        self.agent: AgentMultiplexer = AgentMultiplexer()
        for a in agents:
            self.agent.add_agent(a)

        self.findings_dir_path: pathlib.Path | None = findings_dir_path
        self.max_attempts_of_test_redo: int = max_attempts_of_test_redo
        self.max_test_cases_per_epoch: int = max_test_cases_per_epoch
        self.stop_on_find: bool = stop_on_find
        self.wait_time_before_test_end: int = wait_time_before_test_end
        self.target_restart_timeout: int = target_restart_timeout

        self.start_time: float = time.time()
        self.end_time: float | None = None

        self._logger: logging.Logger = logging.getLogger('engine')

        try:
            os.makedirs(self.findings_dir_path, exist_ok=True)
        except OSError as err:
            self._logger.error("Could not create findings directory %s: %s",
                               self.findings_dir_path, err)
        else:
            self._logger.info("Created findings directory %s",
                              self.findings_dir_path)

        self._current_epoch: int | None = None
        """Current epoch in the fuzzing process."""

        self._total_cases_fuzzed: int = 0
        """Total number of test cases fuzzed during the current epoch/run execution."""

        self._epoch_cases_fuzzed: int | None = None
        """Number of test cases fuzzed during the current epoch."""

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

        return self._total_cases_fuzzed / self.runtime

    def run(self) -> bool:
        """Start to fuzz the protocol specified.

        Returns:
            `True` if the protocol is successfully fuzzed, `False` otherwise.
        """

        # create the findings directory for the current run
        self._run_id = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0).isoformat().replace(":", "-")
        self._run_path = self.findings_dir_path / pathlib.Path(self._run_id)
        try:
            os.makedirs(self._run_path, exist_ok=True)
        except OSError as err:
            self._logger.error(
                "Could not create directory %s: %s", self._run_path, err)
            return False

        self._logger.debug(
            "Created current run findings directory %s", self._run_path)

        self.start_time = time.time()
        self._total_cases_fuzzed = 0

        try:
            paths = self.agent.get_supported_paths(self.protocol.name)
        except AgentError:
            return False

        result = self._fuzz_protocol(paths)

        self.agent.on_shutdown()

        self.end_time = time.time()
        return result

    def _fuzz_protocol(self, paths: list[list[str]]) -> bool:
        """Fuzz all the possible routes for the current protocol.

        This function iterates over all the supported paths in the current protocol and fuzzes each
        path using the `fuzz_epoch` method. If there is no specific supported path, this function
        iterates over all the possible paths in the current protocol.

        Args:
            paths: List of paths supported by the agents.

        Returns:
            `True` if all the paths were successfully fuzzed without errors, `False` otherwise.
        """

        self._current_epoch = 0
        self._logger.info("Fuzzing of protocol %s started", self.protocol.name)

        res = True
        epoch_seed_generator = Random(
            hashlib.sha512(self.main_seed.to_bytes()).digest())

        if len(paths) > 0:
            paths = [self.protocol.build_path(path) for path in paths]
            paths = [p for p in paths if p is not None]
        else:
            paths = None

        for path in self.protocol.iterate_as(self.actor, allowed_paths=paths):
            epoch_seed = epoch_seed_generator.randint(0, sys.maxsize * 2 + 1)
            res = self.fuzz_epoch(path, epoch_seed)
            if not res:
                break

        self._logger.info("Fuzzing of protocol %s ended", self.protocol.name)
        self._current_epoch = None

        return res

    def fuzz_epoch(self, path: ProtocolPath, seed: int) -> bool:
        """Fuzz a single epoch on the given path.

        Args:
            path: Path in the protocol to be fuzzed.
            seed: Seed value for the current epoch.

        Returns:
            bool: `True` if the epoch is completed without errors, `False` otherwise.
        """

        try:
            skipped = self.agent.skip_epoch(
                ExecutionContext(self.protocol.name, path))
        except AgentError as e:
            self._logger.error(str(e))
            if self._current_epoch is None:
                self.agent.on_shutdown()
            return False

        if skipped:
            self._logger.info("Epoch skipped by agents")
            if self._current_epoch is None:
                self.agent.on_shutdown()
            return False

        if self._current_epoch is not None:
            self._current_epoch += 1
            self._logger.info("Epoch #%s started", self._current_epoch)
        else:
            self._logger.info("Epoch started")

        self._epoch_seed = seed
        self._logger.info('Seed: %s', self._epoch_seed)

        # first we generate the mutations only
        success = self._fuzz_single_epoch(path, generate_only=True)

        # then we apply the mutations
        if success:
            success = self._fuzz_single_epoch(path)

        if self._current_epoch is not None:
            self._logger.info("Epoch #%s terminated", self._current_epoch)
        else:
            self._logger.info("Epoch terminated")
            self.agent.on_shutdown()

        return success

    def _fuzz_single_epoch(self, path: ProtocolPath, generate_only: bool = False) -> bool:
        """Fuzz a single epoch for the current protocol.

        Args:
            path: Path in the protocol to be fuzzed.
            generate_only: A flag indicating whether mutations should be only generated and not
            applied.

        Returns:
            `True` if the epoch is completed without errors, `False` otherwise.
        """

        if generate_only:
            self._logger.info(
                "Generating mutations for epoch #%s", self._current_epoch)

        self._logger.debug("Current seed: %s", self._epoch_seed)
        self._epoch_random = Random(hashlib.sha512(
            self._epoch_seed.to_bytes()).digest())

        # if we have only to generate mutations, run a single test case with `generate_only=True`
        if generate_only:
            success, _ = self._fuzz_single_test_case(path, None, True)
            if success:
                self._logger.info("Generated %s mutations",
                                  len(self._epoch_mutations))
            else:
                self._logger.error(
                    "An error occurred while generating the mutations")
            return success

        self._epoch_cases_fuzzed = 0

        # otherwise, run a test case for each mutation
        for mutation in self._epoch_mutations:
            success, fault_found = self._fuzz_single_test_case(path, mutation)
            if not success:
                self._logger.error(
                    "An error occurred while executing the epoch")
                break

            self._epoch_cases_fuzzed += 1
            self._total_cases_fuzzed += 1

            if fault_found and self.stop_on_find:
                break

        return success

    def _test_case_setup(self, ctx: ExecutionContext, attempt_count: int):
        """Prepare everything for the execution of a test case.

        Arguments:
            attempt_count: The number of the current attempt that is being run.
            ctx: The execution context to send to all the agents.

        Raises:
            TestCaseExecutionError: If the test setup was not completed successfully.
        """

        part_of_epoch = self._epoch_cases_fuzzed is not None

        try:
            self.agent.on_test_start(ctx)
        except AgentError as e:
            raise TestCaseExecutionError(str(e)) from e

        for enc in self.encoders:
            enc.reset()

        for dec in self.decoders:
            dec.reset()

        started_pubs: list[Publisher] = []

        try:
            for pub in set(self.actors.values()):
                pub.start()
                started_pubs.append(pub)
        except PublisherOperationError as e:
            msg = "Failed to start a publisher: " + str(e)
            for pub in started_pubs:
                try:
                    pub.stop()
                except PublisherOperationError:
                    pass
            raise TestCaseExecutionError(msg) from e

        if part_of_epoch:
            self._logger.info("Test case #%s started",
                              self._epoch_cases_fuzzed+1)
        else:
            self._logger.info("Test case started")

        self._logger.info("Attempt #%s", attempt_count)

    def _test_case_teardown(self):
        """Do everything that is necessary to clean up after the execution of a test case.

        Raises:
            TestCaseExecutionError: If any of the agents wants to stop the execution.
        """

        part_of_epoch = self._epoch_cases_fuzzed is not None

        for pub in set(self.actors.values()):
            try:
                pub.stop()
            except PublisherOperationError as e:
                self._logger.warning("Failed to stop a publisher: %s", e)

        if part_of_epoch:
            self._logger.info("Test case #%s stopped",
                              self._epoch_cases_fuzzed+1)
        else:
            self._logger.info("Test case stopped")

        try:
            self.agent.on_test_end()
        except AgentError as e:
            raise TestCaseExecutionError(str(e)) from e

    def _fuzz_single_test_case(self, path: ProtocolPath, mutation: tuple[Mutation, str] | None, generate_only: bool = False, attempt_left: int | None = None) -> tuple[bool, bool]:
        """Fuzz a given test case from a given path.

        Args:
            path: Path in the protocol to be fuzzed.
            mutation: Mutation to use, or `None` if no mutation should be used.
            generate_only (optional): A flag indicating whether mutations should be only generated 
                and not applied. Defaults to `False`.
            attempt_left (optional): Number of attempts left for the test case. Defaults to 
                `max_test_cases_per_epoch`.

        Returns:
            A tuple where the first element is `True` if the test case completed successfully, 
            `False` otherwise. In case the first element is `True`, the second element specifies if 
            a fault was found.
        """

        if attempt_left is None:
            attempt_left = self.max_test_cases_per_epoch

        if attempt_left == 0:
            self._logger.warning("Exhausted all attempts")
            return

        ctx = ExecutionContext(self.protocol.name, path)
        mutations_generated = False
        fault_detected = False
        try:
            self._test_case_setup(
                self.max_attempts_of_test_redo-attempt_left+1, ctx)

            timestamp_last_message_sent = time.time()
            for msg in path:
                pub = self.actors[msg.src]

                while not pub.data_available():
                    delta = time.time() - timestamp_last_message_sent
                    if delta >= self.wait_time_before_test_end:
                        msg = ("Timeout reached (threshold: "
                               f"{self.wait_time_before_test_end: .4f}s)")
                        raise TimeoutExecutionError(msg)

                self._logger.debug("Data available from %s", msg.src)

                try:
                    data = pub.receive()
                except PublisherOperationError as e:
                    msg = "Error while receiving message: " + str(e)
                    raise TestCaseExecutionError(msg) from e

                to_be_fuzzed = path.pos+1 == len(path.path)
                self._logger.debug("Data received %s", data)
                self._logger.debug("To be fuzzed: %s", to_be_fuzzed)

                # try to apply all the decoding steps, this even if the message is from the main
                # actor becuase maybe it contains some info needed to decode future messages
                decoded_data = data
                try:
                    for dec in self.decoders:
                        self._logger.debug(
                            "Decoding message with decoder %s", type(dec))
                        self._logger.debug("Message: %s", decoded_data)
                        decoded_data = dec.decode(
                            decoded_data, self.protocol, msg, to_be_fuzzed)
                except DecodingError as e:
                    msg = "Error while decoding message: " + str(e)
                    raise TestCaseExecutionError(msg) from e

                self._logger.debug("Decoded data %s", decoded_data)

                if to_be_fuzzed:
                    try:
                        self._logger.debug(
                            "Parsing message with parser %s", type(msg.msg))
                        msg.msg.parse(decoded_data)
                    except MessageParsingError as e:
                        msg = "Error while parsing message: " + str(e)
                        raise TestCaseExecutionError(msg) from e

                    # if the flag is set, generate mutations and stop the fuzzing process
                    if generate_only:
                        self._logger.debug("Generating mutations")
                        self._epoch_mutations = self._generate_mutations(
                            msg.msg)
                        mutations_generated = True
                    else:
                        # apply the mutation
                        self._logger.debug("Applying mutation")
                        mutated_data = mutation[0].apply(
                            msg.msg.get_content(mutation[1]))
                        msg.msg.set_content(mutation[1], mutated_data)
                        data = msg.msg.raw()
                        self._logger.debug("Mutated data %s", data)

                        try:
                            for enc in self.encoders:
                                self._logger.debug(
                                    "Encoding message with encoder %s", type(enc))
                                self._logger.debug("Message: %s", data)
                                data = enc.encode(data, self.protocol, msg)
                        except EncodingError as e:
                            msg = "Error while encoding message: " + str(e)
                            raise TestCaseExecutionError(msg) from e

                        self._logger.debug("Encoded data %s", data)

                if not mutations_generated:
                    # send the message data to the destination publisher
                    try:
                        self._logger.debug(
                            "Sending message to publisher %s", msg.dst)
                        self.actors[msg.dst].send(data)
                    except PublisherOperationError as e:
                        msg = "Error while sending message: " + str(e)
                        raise TestCaseExecutionError(msg) from e

                    timestamp_last_message_sent = time.time()

                if not to_be_fuzzed:
                    continue

                try:
                    is_to_redo = self.agent.redo_test()
                except AgentError as e:
                    raise TestCaseExecutionError(str(e)) from e

                if is_to_redo:
                    if mutations_generated:
                        self._epoch_mutations = []
                    self._logger.info('An agent asked to redo the test case')
                    self._test_case_teardown()
                    self._logger.info('Redoing test case')
                    return self._fuzz_single_test_case(path, mutation, generate_only, attempt_left-1)

                if mutations_generated:
                    continue

                try:
                    fault_detected = self.agent.fault_detected()
                except AgentError as e:
                    raise TestCaseExecutionError(str(e)) from e

                if fault_detected:
                    self._logger.info("Fault detected")

                    try:
                        data = self.agent.get_data()
                    except AgentError as e:
                        raise TestCaseExecutionError(str(e)) from e

                    # TODO: write the data somewhere

            self._test_case_teardown()
        except TestCaseExecutionError as e:
            self._logger.error("%s", str(e))
            try:
                self._test_case_teardown()
            except TestCaseExecutionError:
                pass
            return False, False

        return True, fault_detected

    def _generate_mutations(self, data: Message) -> list[tuple[Mutation, str]]:
        """Generates a list of mutations for the given data.

        Parameters:
            data: The data for which mutations need to be generated.

        Returns:
            list[tuple[Mutation, str]]: A list of mutations generated for the given data.
        """

        # instantiate all the mutators with a seed
        mutators: list[tuple[Mutator, str]] = []
        for mutator, fuzzable_path in data.mutators():
            mutator_seed = self._epoch_random.randint(0, sys.maxsize * 2 + 1)
            m = mutator(seed=mutator_seed)
            mutators.append((m, fuzzable_path))

        # generate the mutations
        mutations: list[tuple[Mutation, str]] = []
        while True:
            mutator, fuzzable_path = self._epoch_random.choice(mutators)
            mutation = mutator.mutate(data.get_content(fuzzable_path))
            if mutation not in mutations:
                mutations.append((mutation, fuzzable_path))

            # if the mutator used is exhausted then remove it from the list of mutators
            try:
                mutator.next()
            except MutatorCompleted:
                mutators.remove((mutator, fuzzable_path))

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

        try:
            skipped = self.agent.skip_epoch(
                ExecutionContext(self.protocol.name, path))
        except AgentError as e:
            self._logger.error(str(e))
            self.agent.on_shutdown()
            return

        if skipped:
            self._logger.info("Test skipped by agents due to skipped epoch")
            self.agent.on_shutdown()
            return

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
