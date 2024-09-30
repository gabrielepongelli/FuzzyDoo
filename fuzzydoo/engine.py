import time
import logging
import os
import errno
import datetime
import hashlib
import sys
import pathlib
from random import Random
from typing import List, Any
from threading import Lock

from .protocol import Protocol
from .proto import Message
from .publisher import Publisher
from .monitor import Monitor
from .encoder import Encoder
from .decoder import Decoder
from .fuzzable import Fuzzable
from .mutator import Mutation, MutatorCompleted
from .utils import Path


class Engine:
    """The `Engine` class is the main component of the FuzzyDoo fuzzing framework. It orchestrates 
    the entire fuzzing process, including protocol fuzzing, message mutation, encoding, decoding, 
    monitoring, and result handling.

    The `Engine` class is responsible for managing the fuzzing process. It initializes the 
    necessary components, such as protocols to be fuzzed, message sources, target systems, 
    monitors, encoders, decoders, and result storage. It also provides methods to start the fuzzing 
    process, calculate runtime and execution speed, and handle target system restarts.

    Attributes:
        main_seed: Seed value for randomization.
        protocols: List of protocols to be fuzzed.
        source: Source of messages that will be fuzzed.
        target: Target system to which the mutated messages will be forwarded.
        monitors: List of monitors to check the target system's status.
        encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
        decoders: List of decoders to decode the data received by `source` and prepare them to 
            be fuzzed.
        findings_dir_path: Path to the directory where findings will be stored.
        max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
        stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a 
            vulnerability.
        wait_time_before_epoch_end: Time to wait before terminating an epoch in case no message 
            is received by `source` or by `target` (in seconds).
        target_restart_timeout: Time to wait after restarting the target system and before 
            checking for its liveness (in seconds).


    Todo: add an example once everything is done properly.
    """

    def __init__(self,
                 main_seed: int,
                 protocols: List[Protocol],
                 source: Publisher,
                 target: Publisher,
                 monitors: List[Monitor],
                 encoders: List[Encoder],
                 decoders: List[Decoder],
                 findings_dir_path: pathlib.Path,
                 max_test_cases_per_epoch: int,
                 stop_on_find: bool,
                 wait_time_before_epoch_end: int,
                 target_restart_timeout: int):
        """Initialize the `Engine` class with the provided parameters.

        The `Engine` class orchestrates the fuzzing process, managing protocols, message sources, 
        target systems, monitors, encoders, decoders, findings directory, and other parameters.

        Parameters:
            main_seed: Seed value for randomization.
            protocols: List of protocols to be fuzzed.
            source: Source of messages that will be fuzzed.
            target: Target system to which the mutated messages will be forwarded.
            monitors: List of monitors to check the target system's status.
            encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
            decoders: List of decoders to decode the data received by `source` and prepare them to 
                be fuzzed.
            findings_dir_path: Path to the directory where findings will be stored.
            max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
            stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a 
                vulnerability.
            wait_time_before_epoch_end: Time to wait before terminating an epoch in case no message 
                is received by `source` or by `target` (in seconds).
            target_restart_timeout: Time to wait after restarting the target system and before 
                checking for its liveness (in seconds).
        """

        self.main_seed: int = main_seed
        self.protocols: List[Protocol] = protocols
        self.source: Publisher = source
        self.target: Publisher = target
        self.encoders: List[Encoder] = encoders
        self.decoders: List[Decoder] = decoders
        self.monitors: List[Monitor] = monitors
        self.findings_dir_path: pathlib.Path | None = findings_dir_path
        self.max_test_cases_per_epoch: int = max_test_cases_per_epoch
        self.stop_on_find: bool = stop_on_find
        self.wait_time_before_epoch_end: int = wait_time_before_epoch_end
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

        self._current_epoch: int = 0
        """Current epoch in the fuzzing process."""

        self._epoch_cases_fuzzed: int = 0
        """Number of test cases fuzzed in the current epoch."""

        self._epoch_stop: bool = False
        """Flag indicating whether the current epoch has been stopped."""

        self._epoch_stop_reason: str | None = None
        """Reason why the current epoch stopped."""

        self._current_proto: Protocol | None = None
        """Current protocol being fuzzed."""

        self._current_msg: Message | None = None
        """Current message being fuzzed inside the current protocol."""

        self._current_route: Path | None = None
        """Current route in the protocol tree being fuzzed."""

        self._num_cases_actually_fuzzed: int = 0
        """Number of test cases actually fuzzed during the current run."""

        self._run_id: str | None = None
        """Unique identifier for the current fuzzing run."""

        self._run_path: pathlib.Path | None = None
        """Path to the directory where findings relative to the current run will be stored."""

        self._timestamp_last_message_sent: float | None = None
        """Timestamp of the last message sent to the source/target system."""

        self._timestamp_last_message_sent_lock: Lock = Lock()
        """Lock for the `_timestamp_last_message_sent` attribute."""

        self._epoch_seed_generator: Random = Random(
            hashlib.sha512(self.main_seed).digest())
        """Random number generator used to generate seeds for each epoch."""

        self._epoch_seed: int | None = None
        """Seed value for the current epoch."""

        self._epoch_random: Random | None = None
        """Random number generator used inside the current epoch."""

        self._epoch_mutations: List[Mutation] = []
        """List of mutations to perform during the current epoch."""

        for mon in monitors:
            mon.add_target(self.target)

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

    def _restart_target(self):
        """Restart the target system and check its liveness.

        This function attempts to restart the target system using the available monitors. After 
        restarting, it waits for a specified amount of time to allow the system to settle and 
        finally it checks the liveness of the target system using the monitors.
        """

        self._logger.info("Restarting target")
        restarted = False
        for monitor in self.monitors:
            if monitor.restart_target():
                self._logger.info(
                    "Giving the process %s seconds to settle in", self.target_restart_timeout)
                time.sleep(self.target_restart_timeout)
                restarted = True
                break

        if restarted:
            is_alive = True
            for monitor in self.monitors:
                if not monitor.is_target_alive():
                    self._logger.error(
                        "Target is not alive after restart... stopping fuzzing")
                    is_alive = False
                    self._epoch_stop_reason = "Target is not alive after restart"
                    break
            if is_alive:
                self._logger.info("Target alive")
        else:
            self._logger.error(
                "No monitor could restart the target... stopping fuzzing")
            self._epoch_stop_reason = "No monitor could restart the target"

        self._epoch_stop = not (restarted and is_alive)

    def run(self) -> int:
        """Start to fuzz all the protocols specified.

        Returns:
            int: `0` if the fuzzing process completed successfully, `1` otherwise.
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
                    return 1
            else:
                self._logger.debug(
                    "Created current run findings directory %s", self._run_path)

        self.start_time = time.time()
        self._num_cases_actually_fuzzed = 0

        # fuzz all protocols in the engine
        for proto in self.protocols:
            self._current_proto = proto
            self._fuzz_protocol()

        self.end_time = time.time()
        return 0

    def fuzz_epoch(self, path: Path, seed: int):
        """Fuzz a single epoch from a given path.

        Args:
            path: Path in the protocol to be fuzzed.
            seed: Seed value for the current epoch.
        """

        self._current_epoch += 1
        self._current_route = path
        self._epoch_seed = seed

        # first we generate the mutations only
        self._fuzz_protocol_epoch(generate_only=True)

        # then we apply the mutations
        self._fuzz_protocol_epoch()

    def fuzz_single_test_case(self, path: Path, seed: int, mutation_type: str, mutator_state: Any):
        """Fuzz a given test case from a given path.

        Args:
            path: Path in the protocol to be fuzzed.
            seed: Seed value for the current test case.
            mutation_type: Type of mutation to be applied.
            mutator_state: State of the mutator to be used.
        """

        self._logger.info("Replaying test case with seed %s", seed)

        # TODO

    def _fuzz_protocol(self):
        """Fuzz all the possible routes for the current protocol.

        This function iterates over all the possible paths in the current protocol and fuzzes each 
        path using the `fuzz_epoch` method.
        """

        self._current_epoch = 0
        self._logger.info("Fuzzing of protocol %s started",
                          self._current_proto.name)

        for path in self._current_proto:
            self.fuzz_epoch(path, self._epoch_seed_generator.randint(
                0, sys.maxsize * 2 + 1))

        self._logger.info("Fuzzing of protocol %s ended",
                          self._current_proto.name)

    def _generate_mutations(self, data: Fuzzable) -> List[Mutation]:
        """Generates a list of mutations for the given data.

        Parameters:
            data: The data for which mutations need to be generated.

        Returns:
            List[Mutation]: A list of mutations generated for the given data.
        """

        # instantiate all the mutators with a seed
        mutators = []
        for mutator in data.mutators():
            m = mutator(seed=self._epoch_random.randint(
                0, sys.maxsize * 2 + 1))
            mutators.append(m)

        # generate the mutations
        mutations = []
        while True:
            mutator = self._epoch_random.choice(mutators)
            mutation = mutator.mutate(data)
            if mutation not in mutations:
                mutations.append(mutation)

            # if the mutator used is exhausted then remove it from the list of mutators
            try:
                mutator.next()
            except MutatorCompleted:
                mutators.remove(mutator)

            if len(mutators) == 0 or len(mutations) >= self.max_test_cases_per_epoch:
                break

        return mutations

    def _fuzz_protocol_epoch(self, generate_only: bool = False):
        """Fuzz a single epoch for the current protocol.

        Parameters:
            generate_only: A flag indicating whether mutations should be only generated and not applied.
        """
        if generate_only:
            self._logger.info(
                "Generating mutations for epoch #%s", self._current_epoch)
        else:
            self._logger.info("Epoch #%s started", self._current_epoch)

        self._logger.debug("Current seed: %s", self._epoch_seed)

        self._epoch_random = Random(hashlib.sha512(self._epoch_seed).digest())
        self._epoch_stop = False
        self._epoch_stop_reason = None
        self._epoch_cases_fuzzed = 0

        for enc in self.encoders:
            enc.reset()

        for dec in self.decoders:
            dec.reset()

        iter(self._current_route)
        self._current_msg = next(self._current_route)

        self.source.on_message(self._mutate, args=(generate_only,))
        self.source.start()

        # infinite loop waiting for epoch stop or for the timeout to expire
        if not generate_only:
            while not self._epoch_stop:
                time.sleep(0.5)
                with self._timestamp_last_message_sent_lock:
                    delta = time.time() - self._timestamp_last_message_sent
                    if delta >= self.wait_time_before_epoch_end:
                        self.source.stop()
                        self._epoch_stop = True
                        self._epoch_stop_reason = "Timeout"

        if generate_only:
            self._logger.debug("Generated %s mutations",
                               len(self._epoch_mutations))
        else:
            self._logger.info("Epoch #%s terminated for reason: %s",
                              self._current_epoch, self._epoch_stop_reason)

    def _mutate(self, data: bytes, generate_only: bool):
        """Callback function called on each new message received.

        This function mutates the input message based on the current protocol, message, and fuzzing status.

        Args:
            data: The input data that makes up the new message.
            generate_only: A flag indicating whether mutations should be only generated and not 
                applied.
        """

        with self._timestamp_last_message_sent_lock:
            # update the timestamp so that the engine doesn't try to stop `source` while processing
            # this message
            self._timestamp_last_message_sent = time.time()

        to_be_fuzzed = self._current_msg == self._current_route.path[-1].dst
        if to_be_fuzzed:
            self._logger.info("Test case #%s started",
                              self._epoch_cases_fuzzed + 1)

        # apply all the decoders to the received data
        for dec in self.decoders:
            data = dec.decode(data, self._current_proto,
                              self._current_msg, to_be_fuzzed)

        if to_be_fuzzed:

            # TODO: parse_fuzzable is not part of the Protocol class
            fuzzable_data = self._current_proto.parse_fuzzable(data)

            # if the flag is set, generate mutations and stop the fuzzing process
            if generate_only:
                self._epoch_mutations = self._generate_mutations(fuzzable_data)
                self._epoch_stop = True
                return

            # otherwise, apply one of the previously generated mutations to the data
            self._epoch_mutations.pop().apply(fuzzable_data)
            data = fuzzable_data
        else:
            self._current_msg = next(self._current_route)

        # apply all the encoders to the (maybe fuzzed) data
        for enc in self.encoders:
            data = enc.encode(data, self._current_proto, self._current_msg)

        self.target.send(data)
        with self._timestamp_last_message_sent_lock:
            self._timestamp_last_message_sent = time.time()

        if to_be_fuzzed:
            self._num_cases_actually_fuzzed += 1
            self._epoch_cases_fuzzed += 1
            self._logger.info("Test case #%s stopped",
                              self._epoch_cases_fuzzed)

            # check if the target is still alive
            for monitor in self.monitors:
                if not monitor.is_target_alive():

                    # TODO: handle new result (write to file, log, restart target)

                    if self.stop_on_find:
                        self._epoch_stop = True

            if not self._epoch_stop and len(self._epoch_mutations) == 0:
                self._epoch_stop = True
                self._epoch_stop_reason = "Exhausted all test cases"
