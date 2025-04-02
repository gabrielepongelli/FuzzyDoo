import time
import logging
import os
import datetime
import hashlib
import sys
import pathlib
import itertools
from random import Random
from math import ceil
from typing import Literal

import yaml
from more_itertools import first_true, peekable

from .protocol import MessageNode, Protocol, ProtocolPath, Message, PathValidator
from .publisher import Publisher
from .agent import AgentMultiplexer, Agent, ExecutionContext
from .transformer import Encoder, Decoder, Transformer
from .mutator import Mutation, Mutator, MutatorCompleted, MutatorNotApplicable
from .utils.other import opened_w_error

from .utils.errs import *


class Engine:
    """The `Engine` class is the main component of the FuzzyDoo fuzzing framework. It orchestrates
    the entire fuzzing process, including protocol fuzzing, message mutation, encoding, decoding,
    monitoring, and result handling.

    The `Engine` class is responsible for managing the fuzzing process. It initializes the
    necessary components, such as protocols to be fuzzed, message sources, target systems,
    agents, encoders, decoders, and result storage. It also provides methods to start the fuzzing
    process, calculate runtime and execution speed, and handle target system restarts.

    Todo: add an example once everything is done properly.
    """

    main_seed: int
    """Seed value used for randomization."""

    protocol: Protocol
    """Protocol to be fuzzed."""

    actor: str
    """Name of the actor in the protocol to act as."""

    actors: dict[str, Publisher]
    """Mapping of each protocol's actor with the related `Publisher` to use."""

    encoders: list[Encoder]
    """List of encoders."""

    decoders: list[Decoder]
    """List of decoders."""

    findings_dir_path: pathlib.Path | None
    """Path to the directory where findings will be stored."""

    max_attempts_of_test_redo: int
    """Maximum number of attempts to re-perform a test case."""

    max_test_cases_per_epoch: int
    """Maximum number of test cases to be executed per epoch."""

    stop_on_find: bool
    """Flag indicating whether to stop the fuzzing epoch upon finding a vulnerability."""

    produce_findings_anyway: bool
    """Flag indicating whether to produce findings even if no fault is detected."""

    wait_time_before_test_end: int
    """Seconds to wait before terminating a single test in case no message is received."""

    start_time: float | None
    """Time since epoch taken at the beginning of a run."""

    end_time: float | None
    """Time since epoch taken at the end of a run."""

    skip_tests: dict[int, list[int] | Literal[True]]
    """A dictionary that, for each epoch index, contains a list of the test case indexes to skip.
    If the index of an epoch is not present as key in the dictionary, then the whole epoch is
    executed. If instead its index is present as a key, its corresponding value can be either:
        1. A list of test case indexes. In this case, all those test cases will not be performed
            for the epoch specified.
        2. The value `True`. In this case all the epoch will be skipped.
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
                 produce_findings_anyway: bool,
                 wait_time_before_test_end: int,
                 skip_tests: dict[int, list[int] | Literal[True]]):
        """Initialize the `Engine` class with the provided parameters.

        The `Engine` class orchestrates the fuzzing process, managing protocols, message sources,
        target systems, monitors, encoders, decoders, findings directory, and other parameters.

        Parameters:
            main_seed: Seed value used for randomization.
            protocol: Protocol to be fuzzed.
            actor: Name of the actor in the protocol to act as.
            actors: Mapping of each protocol's actor with the related `Publisher` to use.
            encoders: List of encoders to be used during the fuzzing process.
            decoders: List of decoders to be used during the fuzzing process.
            findings_dir_path: Path to the directory where findings will be stored.
            max_attempts_of_test_redo: Maximum number of attempts to re-perform a test case.
            max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
            stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a
                vulnerability.
            produce_findings_anyway: Flag indicating whether to produce findings even if no fault
                is detected.
            wait_time_before_test_end: Time to wait before terminating a single test in case no
                message is received by `source` or by `target` (in seconds).
            skip_tests: A dictionary that, for each epoch index, contains a list of the test case
                indexes to skip.
        """

        self.main_seed = main_seed
        self.protocol = protocol
        self.actor = actor
        self.actors = actors
        self.encoders = encoders
        self.decoders = decoders
        self.findings_dir_path = findings_dir_path
        self.max_attempts_of_test_redo = max_attempts_of_test_redo
        self.max_test_cases_per_epoch = max_test_cases_per_epoch
        self.stop_on_find = stop_on_find
        self.produce_findings_anyway = produce_findings_anyway
        self.wait_time_before_test_end = wait_time_before_test_end
        self.start_time = None
        self.end_time = None
        self.skip_tests = skip_tests

        self._logger: logging.Logger = logging.getLogger('Engine')
        """Logger instance to use."""

        try:
            os.makedirs(self.findings_dir_path, exist_ok=True)
        except OSError as err:
            self._logger.error("Could not create findings directory %s: %s",
                               self.findings_dir_path, err)
        else:
            self._logger.info("Created findings directory %s",
                              self.findings_dir_path)

        self._agent: AgentMultiplexer = AgentMultiplexer()
        """Mux of agents to use."""

        for a in agents:
            self._agent.add_agent(a)

        self._current_epoch: int = None
        """Current epoch in the fuzzing process."""

        self._current_test_case: int | None = None
        """Current test case during the current epoch."""

        self._run_id: str | None = None
        """Unique identifier for the current fuzzing run."""

        self._run_path: pathlib.Path | None = None
        """Path to the directory where findings relative to the current run will be stored."""

        self._epoch_seed: int | None = None
        """Seed value for the current epoch."""

        self._epoch_random: Random | None = None
        """Random number generator used inside the current epoch."""

        self._epoch_mutations: list[Mutation] = []
        """List of mutations to perform during the current epoch."""

    @property
    def runtime(self) -> float:
        """The total runtime of the fuzzing engine in seconds, or `0.0` if no run was started."""

        if self.start_time is None:
            return 0.0

        if self.end_time is not None:
            t = self.end_time
        else:
            t = time.time()
        return t - self.start_time

    def _setup_generic_run(self):
        """Perform the required setup for a generic run.

        For generic run is intended a run over a protocol, a run over a single epoch, or a run over
        a single test case.

        This method performs the following actions:
        1. Set a new run id.
        2. Create a new findings directory for the current run.

        Raises:
            SetupFailedError: If any error occurs during setup.
        """

        self._run_id = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0).isoformat().replace(":", "-")

        # create the findings directory for the current run
        self._run_path = self.findings_dir_path / pathlib.Path(self._run_id)
        try:
            os.makedirs(self._run_path, exist_ok=True)
        except OSError as e:
            raise SetupFailedError(f"Could not create directory {self._run_path}: {e}") from e

        self._logger.debug(
            "Created current run findings directory %s", self._run_path)

    def run(self) -> bool:
        """Start to fuzz the protocol specified.

        Returns:
            `True` if the protocol is successfully fuzzed, `False` otherwise.
        """

        self._logger.info("Starting run setup")

        self._logger.info("Main seed: %s", hex(self.main_seed))

        try:
            self._setup_generic_run()
        except SetupFailedError as e:
            self._logger.error("%s", str(e))
            self._logger.error("Run setup failed")
            return False
        self._logger.info("Run setup completed")

        self.start_time = time.time()

        try:
            paths = self._agent.get_supported_paths(self.protocol.name)
        except AgentError:
            return False

        result = self._fuzz_protocol(paths)

        self.end_time = time.time()
        return result

    def replay(self, n_epoch: int, seed: int, n_test_case: int | None = None) -> bool:
        """Replay the epoch/test case specified using the given seed.

        Args:
            n_epoch: Epoch number to replay.
            seed: Seed value to use for the replay.
            n_test_case (optional): Test case number to replay. If `None` is provided, the entire
                epoch will be replayed. Defaults to `None`.

        Returns:
            `True` if the epoch is successfully fuzzed, `False` otherwise.
        """

        self._logger.info("Starting run setup")

        self._logger.info("Main seed: %s", hex(self.main_seed))

        try:
            self._setup_generic_run()
        except SetupFailedError as e:
            self._logger.error("%s", str(e))
            self._logger.error("Run setup failed")
            return False
        self._logger.info("Run setup completed")

        self.start_time = time.time()

        try:
            paths = self._agent.get_supported_paths(self.protocol.name)
        except AgentError:
            return False

        self._current_epoch = n_epoch - 1
        if len(paths) > 0:
            paths = [self.protocol.build_path(path) for path in paths]
            paths = [p for p in paths if p is not None]
        else:
            paths = None

        path = next(itertools.islice(
            self.protocol.iterate_as(self.actor, allowed_paths=paths), n_epoch - 1, None))
        result = self._run_epoch(path, seed, n_test_case)
        self._current_epoch = None

        self.end_time = time.time()
        return result

    def _fuzz_protocol(self, paths: list[list[dict[str, str | bool]]]) -> bool:
        """Fuzz all the possible routes for the current protocol.

        This function iterates over all the supported paths in the current protocol and fuzzes each
        path using the `_run_epoch` method. If there is no specific supported path, this function
        iterates over all the possible paths in the current protocol.

        Args:
            paths: List of paths supported by the agents.

        Returns:
            `True` if all the paths were successfully fuzzed without errors, `False` otherwise.
        """

        self._logger.info("Fuzzing of protocol %s started", self.protocol.name)

        self._current_epoch = 0
        epoch_seed_generator = Random(
            hashlib.sha512(self.main_seed.to_bytes(ceil(self.main_seed.bit_length() / 8))).digest())

        if len(paths) > 0:
            paths = [self.protocol.build_path(path) for path in paths]
            paths = [p for p in paths if p is not None]
        else:
            paths = None

        errors_occurred = False
        for path in self.protocol.iterate_as(self.actor, allowed_paths=paths):
            epoch_seed = epoch_seed_generator.randint(0, sys.maxsize * 2 + 1)
            success = self._run_epoch(path, epoch_seed)
            errors_occurred = errors_occurred or not success

        self._logger.info("Fuzzing of protocol %s ended", self.protocol.name)
        self._current_epoch = None

        return not errors_occurred

    def _epoch_setup(self, ctx: ExecutionContext):
        """Prepare everything for the execution of an epoch.

        Arguments:
            ctx: The execution context to send to all the agents.

        Raises:
            SetupFailedError: If the epoch setup was not completed successfully.
        """

        self._logger.info("Starting epoch setup")

        try:
            self._agent.on_epoch_start(ctx)
        except AgentError as e:
            try:
                self._agent.on_epoch_end()
            except AgentError:
                pass
            raise SetupFailedError(str(e)) from e

        self._logger.info("Epoch setup completed")

    def _epoch_teardown(self):
        """Do everything that is necessary to clean up after the execution of an epoch.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        self._logger.info("Epoch #%s terminated", self._current_epoch)
        self._agent.on_epoch_end()

    def _run_epoch(self, path: ProtocolPath, seed: int, n_test_case: int | None = None) -> bool:
        """Run a single epoch on the given path.

        Args:
            path: Path in the protocol to be fuzzed.
            seed: Seed value for the current epoch.
            n_test_case (optional): The number of the single test case to be executed. If `None` is
                provided, the entire epoch will be executed. Defaults to `None`.

        Returns:
            `True` if the epoch is completed without errors, `False` otherwise.
        """

        self._current_epoch += 1
        if self.skip_tests.get(self._current_epoch, []) is True:
            self._logger.info("Epoch #%d skipped", self._current_epoch)
            return True

        try:
            skipped = self._agent.skip_epoch(
                ExecutionContext(self.protocol.name, self._current_epoch, path))
        except AgentError as e:
            self._logger.error("%s", str(e))
            return False

        if skipped:
            self._logger.info("Epoch #%d skipped by agents", self._current_epoch)
            return True

        ctx = ExecutionContext(self.protocol.name, self._current_epoch, path)
        try:
            self._epoch_setup(ctx)
        except SetupFailedError as e:
            self._logger.error("%s", str(e))
            self._logger.error("Epoch setup failed")
            return False

        self._logger.info("Epoch #%s started", self._current_epoch)

        self._epoch_seed = seed
        self._logger.info('Seed: %s', hex(self._epoch_seed))

        # first we generate the mutations only
        self._epoch_mutations = []
        success = self._fuzz_path(path, generate_only=True)

        # then we apply the mutations
        if success:
            success = self._fuzz_path(path, n_test_case=n_test_case)

        try:
            self._epoch_teardown()
        except AgentError as e:
            self._logger.error("%s", str(e))
            return False

        return success

    def _fuzz_path(self, path: ProtocolPath, generate_only: bool = False, n_test_case: int | None = None) -> bool:
        """Fuzz the specified protocol path.

        Args:
            path: Path in the protocol to be fuzzed.
            generate_only: A flag indicating whether mutations should be only generated and not
                applied.
            n_test_case (optional): The number of the single test case to be executed. If `None` is
                provided, the entire epoch will be executed. Defaults to `None`.

        Returns:
            `True` if the epoch is completed without errors, `False` otherwise.
        """

        if generate_only:
            self._logger.info("Generating mutations for epoch #%s", self._current_epoch)

        self._epoch_random = Random(hashlib.sha512(
            self._epoch_seed.to_bytes(ceil(self._epoch_seed.bit_length() / 8))).digest())

        if generate_only:
            success, _ = self._fuzz_single_test_case(path, None)
            if success:
                self._logger.info("Generated %s mutations", len(self._epoch_mutations))
            else:
                self._logger.error("An error occurred while generating the mutations")
            return success

        tests_to_skip: list[int] = self.skip_tests.get(self._current_epoch, [])

        # if we have a specific test case to run, run that test case
        if n_test_case is not None:
            self._current_test_case = n_test_case - 1
            try:
                self._epoch_mutations = [self._epoch_mutations[self._current_test_case]]
            except IndexError:
                self._logger.error("Test case number %s does not exist", n_test_case)
                return False
        else:
            self._current_test_case = 0

        # otherwise, run a test case for each mutation
        for mutation in self._epoch_mutations:
            self._current_test_case += 1

            if self._current_test_case in tests_to_skip:
                self._logger.info('Test case #%d skipped', self._current_test_case)
                success = True
                continue

            success, fault_found = self._fuzz_single_test_case(path, mutation)
            if not success:
                self._logger.error("An error occurred while executing the epoch")
                break

            if fault_found and self.stop_on_find:
                break

        self._current_test_case = None
        return success

    def _produce_case_report(self, path: ProtocolPath, mutation: Mutation) -> bytes:
        """Generate a detailed report for a single test case in YAML format.

        This method creates a comprehensive report containing information about the current run,
        the specific test case, and the applied mutation.

        Args:
            path: The path in the protocol that has been fuzzed.
            mutation: The mutation applied.

        Returns:
            bytes: A YAML-formatted report as a bytes object.

        Note:
            The report structure includes:
            - Run information (seed, protocol, actor)
            - Case information (path, epoch, seed, case number, mutated message)
            - Mutation details (mutated element, field, original and mutated values)
        """

        report = {
            "run": {
                "seed": hex(self.main_seed),
                "protocol": self.protocol.name,
                "actor": self.actor,
            },

            "case": {
                "path": ' -> '.join(path.names),
                "epoch": self._current_epoch,
                "epoch_seed": hex(self._epoch_seed),
                "case": self._current_test_case,
                "mutated_message": path.names[-1]
            },

            "mutation": {
                "mutated_element": mutation.qname,
                "mutated_field": mutation.field_name,
                "original_value": mutation.original_value,
                "mutated_value": mutation.mutated_value
            }
        }

        return yaml.safe_dump(report).encode()

    def _save_findings(self, data: list[tuple[str, bytes]]):
        """Save the findings generated during the fuzzing process.

        This function tries to save each finding in a new directory inside `self._run_path`. If an
        error occurs for a specific finding record, it logs a warning and skips the record. If
        instead an error occurs while creating the new directory, a warning message is logged and
        no data is saved.

        Args:
            data: The list of findings, where each elements contains:
                1. The name of the file.
                2. The content of the file
        """

        test_case_path = self._run_path / f"{self._current_epoch}-{self._current_test_case}"
        try:
            os.mkdir(test_case_path)
        except OSError as e:
            self._logger.warning("Could not create directory '%s': %s", test_case_path, e)
            self._logger.warning("Skipping saving findings for the current test case")
            return

        for name, content in data:
            finding_path = test_case_path / name
            with opened_w_error(finding_path, "wb") as (f, err):
                if err:
                    self._logger.warning("Failed to save '%s': %s", finding_path, str(err))
                else:
                    f.write(content)

        self._logger.info("Data exported")

    def _test_case_setup(self, ctx: ExecutionContext):
        """Prepare everything for the execution of a test case.

        Args:
            ctx: The execution context to send to all the agents.

        Raises:
            SetupFailedError: If the test setup was not completed successfully.
        """

        try:
            self._agent.on_test_start(ctx)
        except AgentError as e:
            try:
                self._agent.on_test_end()
            except AgentError:
                pass
            raise SetupFailedError(str(e)) from e

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
            for pub in started_pubs:
                try:
                    pub.stop()
                except PublisherOperationError:
                    pass
            raise SetupFailedError("Failed to start a publisher: " + str(e)) from e

    def _test_case_teardown(self, redo: bool = False):
        """Do everything that is necessary to clean up after the execution of a test case.

        Args:
            redo: A flag indicating whether the test case should be redone.

        Raises:
            TestCaseExecutionError: If any of the agents wants to stop the execution.
        """

        if redo:
            try:
                self._agent.on_redo()
            except AgentError as e:
                raise TestCaseExecutionError(str(e), recoverable=False) from e

        for pub in set(self.actors.values()):
            try:
                pub.stop()
            except PublisherOperationError as e:
                self._logger.warning("Failed to stop a publisher: %s", e)

        if self._current_test_case is not None:
            self._logger.info("Test case #%s stopped", self._current_test_case)
        else:
            self._logger.info("Test case stopped")

        try:
            self._agent.on_test_end()
        except AgentError as e:
            raise TestCaseExecutionError(str(e), recoverable=False) from e

    def _fuzz_single_test_case(self, path: ProtocolPath, mutation: Mutation | None, attempt_left: int | None = None) -> tuple[bool, bool]:
        """Fuzz a given test case from a given path.

        Args:
            path: Path in the protocol to be fuzzed.
            mutation: Mutation to use, or `None` if no mutation should be used.
            attempt_left (optional): Number of attempts left for the test case. Defaults to
                `max_test_cases_per_epoch`.

        Returns:
            A tuple where the first element is `True` if the test case completed successfully,
            `False` otherwise. In case the first element is `True`, the second element specifies if
            a fault was found.
        """

        if attempt_left is None:
            attempt_left = self.max_attempts_of_test_redo

        if attempt_left == 0:
            self._logger.warning("Exhausted all attempts")
            return False, False

        generate_only = self._current_test_case is None
        self._logger.info("Starting test case setup")
        try:
            ctx = ExecutionContext(
                self.protocol.name,
                self._current_epoch,
                path,
                test_case=self._current_test_case,
                mutation_path=mutation.qname if mutation is not None else None,
                mutator=mutation.mutator.NAME if mutation is not None else None,
            )
            self._test_case_setup(ctx)
        except SetupFailedError as e:
            self._logger.error("%s", str(e))
            self._logger.error("Test case setup failed")
            return False, False
        self._logger.info("Test case setup completed")

        if not generate_only:
            self._logger.info("Test case #%s started", self._current_test_case)

        self._logger.info("Attempt #%s", self.max_attempts_of_test_redo - attempt_left + 1)

        fault_detected = False
        to_be_fuzzed = False
        validator = PathValidator(path)
        try:
            while not to_be_fuzzed:
                nodes: set[MessageNode] = validator.next_expected_messages()
                pubs: set[tuple[Publisher, str]] = set()
                for node in nodes:
                    pubs.add((self.actors[node.src], node.src))

                # get first publisher among the ones that can receive messages that has something
                pub: tuple[Publisher, str] | None = None
                timestamp_last_message_recvd = time.time()
                data_available = False
                while not data_available:
                    delta = time.time() - timestamp_last_message_recvd
                    if delta >= self.wait_time_before_test_end:
                        msg = f"Timeout reached (threshold: {self.wait_time_before_test_end:.4f}s)"
                        raise TestCaseExecutionError(msg, recoverable=True)
                    try:
                        pub = first_true(pubs, default=None, pred=lambda p: p[0].data_available())
                        data_available = pub is not None
                    except PublisherOperationError as e:
                        msg = f"Error while checking for data availability: {e}"
                        raise TestCaseExecutionError(msg, recoverable=True) from e
                    time.sleep(0.01)

                self._logger.debug("Data available from %s", pub[1])

                try:
                    data = pub[0].receive()
                except PublisherOperationError as e:
                    msg = f"Error while receiving message: {e}"
                    raise TestCaseExecutionError(msg, recoverable=True) from e

                self._logger.debug("Data received %s", data)

                node_it = peekable(nodes)
                for node in node_it:
                    try:
                        parsed_msg = node.msg.parse(data)
                    except MessageParsingError as e:
                        # if is the last one, raise an exception
                        if bool(node_it):
                            continue
                        msg = f"Error while parsing message: {e}"
                        raise TestCaseExecutionError(msg, recoverable=True) from e

                    self._logger.debug("Parsed data with parser %s", parsed_msg.name)

                    # try to apply all the decoding steps, this even if the message is from the main
                    # actor becuase maybe it contains some info needed to decode future messages
                    decoded_msg = parsed_msg
                    try:
                        for dec in self.decoders:
                            self._logger.debug("Decoding data with decoder %s", dec.NAME)
                            decoded_msg = dec.decode(decoded_msg, node.src, node.dst)
                    except DecodingError as e:
                        msg = f"Error while decoding message: {e}"
                        raise TestCaseExecutionError(msg, recoverable=True) from e

                    self._logger.debug("Decoded data %s", decoded_msg.raw())
                    self._logger.debug("Decoded message %s", decoded_msg.name)
                    if decoded_msg.name != parsed_msg.name:
                        self._logger.debug("Wrong message, trying the next one")
                        continue

                    # found the right message
                    if validator.process(decoded_msg, node.src, node.dst):
                        break
                else:
                    # if the loop didn't end because of a break then the message received is unknown
                    msg = f"Unexpected message received: {decoded_msg.NAME}"
                    raise TestCaseExecutionError(msg, recoverable=True)

                to_be_fuzzed = validator.is_complete()
                self._logger.debug("To be fuzzed: %s", to_be_fuzzed)

                if to_be_fuzzed:
                    # if the flag is set, generate mutations and stop the fuzzing process
                    if generate_only:
                        self._logger.debug("Generating mutations")
                        self._epoch_mutations = self._generate_mutations(decoded_msg)
                        break

                    # apply the mutation
                    data_to_mutate = decoded_msg.get_content(mutation.qname)
                    mutation.apply(data_to_mutate)
                    self._logger.debug("Applied mutation %s", mutation)
                    self._logger.debug("Mutated data %s", decoded_msg.raw())

                # try to apply all the encoding steps, this even if the message has not been
                # modified becuase maybe it is needed by some encoding/decoding method for future
                # messages
                encoded_msg = decoded_msg
                try:
                    for enc in self.encoders:
                        self._logger.debug("Encoding message with encoder %s", enc.NAME)
                        encoded_msg = enc.encode(encoded_msg, node.src, node.dst)
                except EncodingError as e:
                    msg = f"Error while encoding message: {e}"
                    raise TestCaseExecutionError(msg, recoverable=True) from e

                self._logger.debug("Encoded data %s", encoded_msg.raw())

                if to_be_fuzzed:

                    if encoded_msg.delay > 0:
                        self._logger.debug(
                            "Waiting %s seconds before sending the message", encoded_msg.delay)
                        start = time.time()
                        while time.time() - start < encoded_msg.delay:
                            time.sleep(0.1)

                    data = encoded_msg.raw() * encoded_msg.n_replay

                # send the message data to the destination publisher
                try:
                    self._logger.debug("Sending message to publisher %s", node.dst)
                    self.actors[node.dst].send(data)
                except PublisherOperationError as e:
                    msg = f"Error while sending message: {e}"
                    raise TestCaseExecutionError(msg, recoverable=True) from e

                if not to_be_fuzzed:
                    continue

                fault_detected = self._check_fault(path, mutation)

                try:
                    is_to_redo = self._agent.redo_test()
                except AgentError as e:
                    raise TestCaseExecutionError(str(e), recoverable=False) from e

                if is_to_redo:
                    if generate_only:
                        self._epoch_mutations = []
                    self._logger.info('An agent asked to redo the test case')
                    self._test_case_teardown(redo=True)
                    self._logger.info('Redoing test case')
                    return self._fuzz_single_test_case(path, mutation, attempt_left - 1)

            self._test_case_teardown()
        except TestCaseExecutionError as e:
            self._logger.error("%s", str(e))
            try:
                try:
                    is_to_redo = self._agent.redo_test()
                except AgentError as ae:
                    raise TestCaseExecutionError(str(ae), recoverable=False) from ae

                if e.recoverable or is_to_redo:
                    if is_to_redo:
                        self._logger.info('An agent asked to redo the test case')
                        if generate_only:
                            self._epoch_mutations = []
                    self._logger.info('Redoing test case')
                    self._test_case_teardown(redo=True)
                    return self._fuzz_single_test_case(path, mutation, attempt_left - 1)

                self._test_case_teardown()
                return False, False
            except TestCaseExecutionError as e2:
                if e.recoverable:
                    self._logger.error("%s", str(e2))
                return False, False

        if generate_only:
            return True, False

        return True, fault_detected

    def _check_fault(self, path: ProtocolPath, mutation: Mutation) -> bool:
        """_summary_

        _extended_summary_
        """

        try:
            fault_detected = self._agent.fault_detected()
        except AgentError as e:
            raise TestCaseExecutionError(str(e), recoverable=False) from e

        if fault_detected or self.produce_findings_anyway:
            if fault_detected:
                self._logger.info("Fault detected")
                self._agent.on_fault()

            try:
                data = self._agent.get_data()
            except AgentError as e:
                raise TestCaseExecutionError(str(e), recoverable=False) from e

            transformers: list[Transformer] = list(
                {t.__class__: t for t in self.encoders + self.decoders}.values())
            for t in transformers:
                new_data = t.export_data()
                for i, record in enumerate(new_data):
                    new_data[i] = (t.__class__.__name__ + "." + record[0], record[1])
                data.extend(new_data)

            case_report = self._produce_case_report(path, mutation)
            data.append(('report.yaml', case_report))

            self._save_findings(data)
            return True

        self._logger.info("No fault detected")
        return False

    def _generate_mutations(self, data: Message) -> list[Mutation]:
        """Generates a list of mutations for the given data.

        Parameters:
            data: The data for which mutations need to be generated.

        Returns:
            list[Mutation]: A list of mutations generated for the given data.
        """

        # instantiate all the mutators with a seed
        mutators: list[tuple[Mutator, str]] = []
        for mutator, fuzzable_path in data.mutators():
            mutator_seed = self._epoch_random.randint(0, sys.maxsize * 2 + 1)
            m = mutator(seed=mutator_seed)
            mutators.append((m, fuzzable_path))

        # generate the mutations
        mutations: list[Mutation] = []
        while True:
            idx = self._epoch_random.randrange(len(mutators))
            mutator, fuzzable_path = mutators[idx]
            try:
                mutation = mutator.mutate(data.get_content(fuzzable_path))
            except MutatorNotApplicable:
                # if the mutator used cannot be applied to the current data instance then remove it
                mutators = mutators[:idx] + mutators[idx + 1:]
            else:
                if mutation not in mutations:
                    mutations.append(mutation)
                try:
                    mutator.next()
                except MutatorCompleted:
                    # if the mutator used is exhausted then remove it from the list of mutators
                    mutators = mutators[:idx] + mutators[idx + 1:]

            if len(mutators) == 0 or len(mutations) >= self.max_test_cases_per_epoch:
                break

        return mutations


__all__ = ['Engine']
