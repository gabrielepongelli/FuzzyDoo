import time
import logging
import os
import datetime
import hashlib
import sys
import pathlib
import itertools
from random import Random

import yaml

from .protocol import Protocol, ProtocolPath, Message
from .publisher import Publisher
from .agent import AgentMultiplexer, Agent, ExecutionContext
from .transformer import Encoder, Decoder
from .mutator import Fuzzable, Mutation, Mutator, MutatorCompleted, MutatorNotApplicable
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

    wait_time_before_test_end: int
    """Seconds to wait before terminating a single test in case no message is received."""

    start_time: float | None
    """Time since epoch taken at the beginning of a run."""

    end_time: float | None
    """Time since epoch taken at the end of a run."""

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
                 wait_time_before_test_end: int):
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
            wait_time_before_test_end: Time to wait before terminating a single test in case no
                message is received by `source` or by `target` (in seconds).
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
        self.wait_time_before_test_end = wait_time_before_test_end
        self.start_time = None
        self.end_time = None

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
        """The total runtime of the fuzzing engine in seconds, or `0.0` if no run was started."""

        if self.start_time is None:
            return 0.0

        if self.end_time is not None:
            t = self.end_time
        else:
            t = time.time()
        return t - self.start_time

    @property
    def exec_speed(self) -> float:
        """The execution speed of the fuzzing engine in cases per second.

        The execution speed is calculated by dividing the number of cases actually fuzzed by the 
        total runtime of the fuzzing engine.
        """

        rt = self.runtime
        return self._total_cases_fuzzed / rt if rt > 0 else 0.0

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
        self._total_cases_fuzzed = 0

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
        self._total_cases_fuzzed = 0

        try:
            paths = self._agent.get_supported_paths(self.protocol.name)
        except AgentError:
            return False

        self._current_epoch = n_epoch
        if len(paths) > 0:
            paths = [self.protocol.build_path(path) for path in paths]
            paths = [p for p in paths if p is not None]
        else:
            paths = None

        path = next(itertools.islice(
            self.protocol.iterate_as(self.actor, allowed_paths=paths), n_epoch, None))
        result = self._run_epoch(path, seed, n_test_case)
        self._current_epoch = None

        self.end_time = time.time()
        return result

    def _fuzz_protocol(self, paths: list[list[str]]) -> bool:
        """Fuzz all the possible routes for the current protocol.

        This function iterates over all the supported paths in the current protocol and fuzzes each
        path using the `_run_epoch` method. If there is no specific supported path, this function
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
            hashlib.sha512(
                self.main_seed.to_bytes((self.main_seed.bit_length() + 7) // 8 or 1)).digest())

        if len(paths) > 0:
            paths = [self.protocol.build_path(path) for path in paths]
            paths = [p for p in paths if p is not None]
        else:
            paths = None

        for path in self.protocol.iterate_as(self.actor, allowed_paths=paths):
            epoch_seed = epoch_seed_generator.randint(0, sys.maxsize * 2 + 1)
            res = self._run_epoch(path, epoch_seed)
            if not res:
                break

        self._logger.info("Fuzzing of protocol %s ended", self.protocol.name)
        self._current_epoch = None

        return res

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

        try:
            skipped = self._agent.skip_epoch(
                ExecutionContext(self.protocol.name, path))
        except AgentError as e:
            self._logger.error(str(e))
            if self._current_epoch is None:
                self._agent.on_shutdown()
            return False

        if skipped:
            self._logger.info("Epoch skipped by agents")
            if self._current_epoch is None:
                self._agent.on_shutdown()
            return False

        self._logger.info("Starting epoch setup")
        if self._current_epoch is None:
            try:
                self._setup_generic_run()
            except SetupFailedError as e:
                self._logger.error("%s", str(e))
                self._logger.error("Epoch setup failed")
                self._agent.on_shutdown()
                return False
        self._logger.info("Epoch setup completed")

        if self._current_epoch is not None:
            self._current_epoch += 1
            self._logger.info("Epoch #%s started", self._current_epoch)
        else:
            self._logger.info("Epoch started")

        self._epoch_seed = seed
        self._logger.info('Seed: %s', hex(self._epoch_seed))

        # first we generate the mutations only
        self._epoch_mutations = []
        success = self._fuzz_path(path, generate_only=True)

        # then we apply the mutations
        if success:
            success = self._fuzz_path(path, n_test_case=n_test_case)

        if self._current_epoch is not None:
            self._logger.info("Epoch #%s terminated", self._current_epoch)
        else:
            self._logger.info("Epoch terminated")
            self._agent.on_shutdown()

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
            self._epoch_seed.to_bytes((self._epoch_seed.bit_length() + 7) // 8 or 1)).digest())

        self._epoch_cases_fuzzed = 0

        # if we have only to generate mutations, run a single test case with `generate_only=True`
        if generate_only:
            success, _ = self._fuzz_single_test_case(path, None, True)
            if success:
                self._logger.info("Generated %s mutations", len(self._epoch_mutations))
            else:
                self._logger.error("An error occurred while generating the mutations")
            return success

        # if we have a specific test case to run, run that test case
        if n_test_case is not None:
            try:
                mutation = self._epoch_mutations[n_test_case]
            except IndexError:
                self._logger.error("Test case number %s does not exist", n_test_case)
                return False

            success, _ = self._fuzz_single_test_case(path, mutation)

        # otherwise, run a test case for each mutation
        for mutation in self._epoch_mutations:
            success, fault_found = self._fuzz_single_test_case(path, mutation)
            if not success:
                self._logger.error("An error occurred while executing the epoch")
                break

            self._epoch_cases_fuzzed += 1
            self._total_cases_fuzzed += 1

            if fault_found and self.stop_on_find:
                break

        return success

    def _produce_case_report(self, path: ProtocolPath, mutation: tuple[Mutation, str], original_data: Fuzzable) -> bytes:
        """Generate a detailed report for a single test case in YAML format.

        This method creates a comprehensive report containing information about the current run, 
        the specific test case, and the applied mutation.

        Args:
            path: The path in the protocol that has been fuzzed.
            mutation: A tuple containing the mutation object and the associated fuzzable path.
            original_data: The original data before the mutation was applied.

        Returns:
            bytes: A YAML-formatted report as a bytes object.

        Note:
            The report structure includes:
            - Run information (seed, protocol, actor)
            - Case information (path, epoch, seed, case number, mutated message)
            - Mutation details (mutated element, field, original and mutated values)
        """

        if mutation[0].field_name == "":
            mutated_filed = ""
        elif mutation[0].field_name.startswith(original_data.name) and len(mutation[0].field_name) > len(original_data.name):
            mutated_filed = mutation[0].field_name[len(original_data.name) + 1:]
        else:
            mutated_filed = mutation[0].field_name

        report = {
            "run": {
                "seed": self.main_seed,
                "protocol": self.protocol.name,
                "actor": self.actor,
            },

            "case": {
                "path": ' -> '.join(path.names),
                "epoch": self._current_epoch + 1,
                "epoch_seed": hex(self._epoch_seed),
                "case": self._epoch_cases_fuzzed + 1,
                "mutated_message": path.names[-1]
            },

            "mutation": {
                "mutated_element": mutation[1],
                "mutated_field": mutated_filed,
                "original_value": original_data.get_content(mutation[0].field_name),
                "mutated_value": mutation[0].mutated_value
            }
        }

        return yaml.safe_dump(report)

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

        test_case_path = self._run_path / f"{self._current_epoch + 1}-{self._epoch_cases_fuzzed + 1}"
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

    def _test_case_setup(self, ctx: ExecutionContext):
        """Prepare everything for the execution of a test case.

        Arguments:
            ctx: The execution context to send to all the agents.

        Raises:
            SetupFailedError: If the test setup was not completed successfully.
        """

        self._logger.info("Starting test case setup")

        part_of_epoch = self._epoch_cases_fuzzed is not None

        if not part_of_epoch:
            self._setup_generic_run()

        try:
            self._agent.on_test_start(ctx)
        except AgentError as e:
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
            msg = "Failed to start a publisher: " + str(e)
            for pub in started_pubs:
                try:
                    pub.stop()
                except PublisherOperationError:
                    pass
            raise SetupFailedError(msg) from e

        self._logger.info("Test case setup completed")

    def _test_case_teardown(self, generate_only: bool):
        """Do everything that is necessary to clean up after the execution of a test case.

        Args:
            generate_only: A flag indicating whether mutations should be only generated and not applied.

        Raises:
            TestCaseExecutionError: If any of the agents wants to stop the execution.
        """

        part_of_epoch = self._epoch_cases_fuzzed is not None

        for pub in set(self.actors.values()):
            try:
                pub.stop()
            except PublisherOperationError as e:
                self._logger.warning("Failed to stop a publisher: %s", e)

        if not generate_only:
            if part_of_epoch:
                self._logger.info("Test case #%s stopped", self._epoch_cases_fuzzed + 1)
            else:
                self._logger.info("Test case stopped")

        try:
            self._agent.on_test_end()
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
            attempt_left = self.max_attempts_of_test_redo

        if attempt_left == 0:
            self._logger.warning("Exhausted all attempts")
            return False, False

        try:
            ctx = ExecutionContext(self.protocol.name, path)
            if mutation is not None:
                ctx.mutation_path = mutation[1]
                ctx.mutator = mutation[0].mutator.__name__
            self._test_case_setup(ctx)
        except SetupFailedError as e:
            self._logger.error("%s", str(e))
            self._logger.error("Test case setup failed")
            try:
                self._test_case_teardown(generate_only)
            except TestCaseExecutionError:
                pass
            return False, False

        if not generate_only:
            if self._epoch_cases_fuzzed is not None:
                self._logger.info("Test case #%s started",
                                  self._epoch_cases_fuzzed + 1)
            else:
                self._logger.info("Test case started")

        self._logger.info("Attempt #%s", self.max_attempts_of_test_redo - attempt_left + 1)

        fault_detected = False
        mutations_generated = False
        delta = 0.0
        try:
            timestamp_last_message_sent = time.time()
            for msg in path:
                pub = self.actors[msg.src]

                try:
                    data_available = pub.data_available()
                except PublisherOperationError as e:
                    raise TestCaseExecutionError(f"Error while checking for data availability: {e}") from e
                while not data_available:
                    delta = time.time() - timestamp_last_message_sent
                    if delta >= self.wait_time_before_test_end:
                        self._logger.warning("Timeout reached (threshold: %.4fs)",
                                             self.wait_time_before_test_end)
                        break

                    try:
                        data_available = pub.data_available()
                    except PublisherOperationError as e:
                        raise TestCaseExecutionError(f"Error while checking for data availability: {e}") from e
                else:
                    self._logger.debug("Data available from %s", msg.src)

                    try:
                        data = pub.receive()
                    except PublisherOperationError as e:
                        raise TestCaseExecutionError(f"Error while receiving message: {e}") from e

                    to_be_fuzzed = path.pos + 1 == len(path.path)
                    self._logger.debug("Data received %s", data)
                    self._logger.debug("To be fuzzed: %s", to_be_fuzzed)

                    try:
                        self._logger.debug("Parsing message with parser %s", type(msg.msg))
                        parsed_msg = msg.msg.parse(data)
                    except MessageParsingError as e:
                        raise TestCaseExecutionError(f"Error while parsing message: {e}") from e

                    # try to apply all the decoding steps, this even if the message is from the main
                    # actor becuase maybe it contains some info needed to decode future messages
                    decoded_msg = parsed_msg
                    try:
                        for dec in self.decoders:
                            self._logger.debug("Decoding message with decoder %s", type(dec))
                            decoded_msg = dec.decode(decoded_msg, msg.src, msg.dst)
                    except DecodingError as e:
                        raise TestCaseExecutionError(f"Error while decoding message: {e}") from e

                    self._logger.debug("Decoded data %s", decoded_msg.raw())

                    if to_be_fuzzed:
                        # if the flag is set, generate mutations and stop the fuzzing process
                        if generate_only:
                            self._logger.debug("Generating mutations")
                            self._epoch_mutations = self._generate_mutations(decoded_msg)
                            mutations_generated = True
                        else:
                            # apply the mutation
                            self._logger.debug("Applying mutation %s to '%s'", mutation[0], mutation[1])
                            data_to_mutate = decoded_msg.get_content(mutation[1])
                            mutation[0].apply(data_to_mutate)
                            self._logger.debug("Mutated data %s", decoded_msg.raw())

                            encoded_msg = decoded_msg
                            try:
                                for enc in self.encoders:
                                    self._logger.debug(
                                        "Encoding message with encoder %s", type(enc))
                                    encoded_msg = enc.encode(encoded_msg, msg.src, msg.dst)
                            except EncodingError as e:
                                raise TestCaseExecutionError(f"Error while encoding message: {e}") from e

                            data = encoded_msg.raw()
                            self._logger.debug("Encoded data %s", data)
                            if encoded_msg.delay > 0:
                                time.sleep(encoded_msg.delay)

                            if encoded_msg.n_replay > 1:
                                data = data * encoded_msg.n_replay

                    if not mutations_generated:
                        # send the message data to the destination publisher
                        try:
                            self._logger.debug("Sending message to publisher %s", msg.dst)
                            self.actors[msg.dst].send(data)
                        except PublisherOperationError as e:
                            raise TestCaseExecutionError(f"Error while sending message: {e}") from e

                        timestamp_last_message_sent = time.time()

                    if not to_be_fuzzed:
                        continue

                try:
                    is_to_redo = self._agent.redo_test()
                except AgentError as e:
                    raise TestCaseExecutionError(str(e)) from e

                if is_to_redo:
                    if mutations_generated:
                        self._epoch_mutations = []
                    self._logger.info('An agent asked to redo the test case')
                    self._test_case_teardown(generate_only)
                    self._logger.info('Redoing test case')
                    return self._fuzz_single_test_case(path, mutation, generate_only, attempt_left - 1)

                if mutations_generated:
                    continue

                try:
                    fault_detected = self._agent.fault_detected()
                except AgentError as e:
                    raise TestCaseExecutionError(str(e)) from e

                if fault_detected:
                    self._logger.info("Fault detected")

                    try:
                        data = self._agent.get_data()
                    except AgentError as e:
                        raise TestCaseExecutionError(str(e)) from e

                    case_report = self._produce_case_report(path, mutation, data_to_mutate)
                    self._save_findings([('report.yaml', case_report)] + data)

                if delta >= self.wait_time_before_test_end:
                    break

            self._test_case_teardown(generate_only)
        except TestCaseExecutionError as e:
            self._logger.error("%s", str(e))
            try:
                self._test_case_teardown(generate_only)
            except TestCaseExecutionError:
                pass
            return False, False

        if generate_only:
            return mutations_generated, fault_detected
        else:
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
            idx = self._epoch_random.randrange(len(mutators))
            mutator, fuzzable_path = mutators[idx]
            try:
                mutation = mutator.mutate(data.get_content(fuzzable_path))
            except MutatorNotApplicable:
                # if the mutator used cannot be applied to the current data instance then remove it
                mutators = mutators[:idx] + mutators[idx + 1:]
            else:
                if mutation not in mutations:
                    mutations.append((mutation, fuzzable_path))
                try:
                    mutator.next()
                except MutatorCompleted:
                    # if the mutator used is exhausted then remove it from the list of mutators
                    mutators = mutators[:idx] + mutators[idx + 1:]

            if len(mutators) == 0 or len(mutations) >= self.max_test_cases_per_epoch:
                break

        return mutations


__all__ = ['Engine']
