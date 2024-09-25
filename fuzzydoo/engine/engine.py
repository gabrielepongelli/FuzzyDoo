import time
import logging
import os
import errno
import datetime
from pathlib import Path
from typing import List

from ..protocol import Protocol, Message, Route
from ..message_source import MessageSource
from ..target import Target
from ..monitor import Monitor
from ..encoder import Encoder
from ..decoder import Decoder


class Engine:
    """The `Engine` class is the main component of the FuzzyDoo fuzzing framework. It orchestrates 
    the entire fuzzing process, including protocol fuzzing, message mutation, encoding, decoding, 
    monitoring, and result handling.

    The `Engine` class is responsible for managing the fuzzing process. It initializes the 
    necessary components, such as protocols to be fuzzed, message sources, target systems, 
    monitors, encoders, decoders, and result storage. It also provides methods to start the fuzzing 
    process, calculate runtime and execution speed, and handle target system restarts.

    Attributes:
        seed: Seed value for randomization.
        protocols: List of protocols to be fuzzed.
        message_source: Source of messages that will be fuzzed.
        target: Target system to which the messages will be forwarded.
        monitors: List of monitors to check the target system's status.
        encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
        decoders: List of decoders to decode the data received by `message_source` and prepare them 
            to be fuzzed.
        findings_dir_path: Path to the directory where findings will be stored.
        max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
        stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a 
            vulnerability.
        wait_time_before_epoch_end: Time to wait before terminating an epoch in case no message is 
            received by `message_source` or by `target` (in seconds).
        target_restart_timeout: Time to wait after restarting the target system and before checking 
            for its liveness (in seconds).
        start_time: Start time of the fuzzing process.
        end_time: End time of the fuzzing process.


    Todo: add an example once everything is done properly.
    """

    def __init__(self,
                 seed: int,
                 protocols: List[Protocol],
                 message_source: MessageSource,
                 target: Target,
                 monitors: List[Monitor],
                 encoders: List[Encoder],
                 decoders: List[Decoder],
                 findings_dir_path: Path,
                 max_test_cases_per_epoch: int,
                 stop_on_find: bool,
                 wait_time_before_epoch_end: int,
                 target_restart_timeout: int):
        """Initialize the `Engine` class with the provided parameters.

        The `Engine` class orchestrates the fuzzing process, managing protocols, message sources, 
        target systems, monitors, encoders, decoders, findings directory, and other parameters.

        Parameters:
            seed: Seed value for randomization.
            protocols: List of protocols to be fuzzed.
            message_source: Source of messages that will be fuzzed.
            target: Target system to which the messages will be forwarded.
            monitors: List of monitors to check the target system's status.
            encoders: List of encoders to prepare the fuzzed data before sending them to `target`.
            decoders: List of decoders to decode the data received by `message_source` and prepare 
                them to be fuzzed.
            findings_dir_path: Path to the directory where findings will be stored.
            max_test_cases_per_epoch: Maximum number of test cases to be executed per epoch.
            stop_on_find: Flag indicating whether to stop the fuzzing epoch upon finding a 
                vulnerability.
            wait_time_before_epoch_end: Time to wait before terminating an epoch in case no message 
                is received by `message_source` or by `target` (in seconds).
            target_restart_timeout: Time to wait after restarting the target system and before 
                checking for its liveness (in seconds).
        """

        self.seed: int = seed
        self.protocols: List[Protocol] = protocols
        self.message_source: MessageSource = message_source
        self.target: Target = target
        self.encoders: List[Encoder] = encoders
        self.decoders: List[Decoder] = decoders
        self.monitors: List[Monitor] = monitors
        self.findings_dir_path: Path | None = findings_dir_path
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

        self._epoch_stop_reason: str | None = None
        """Reason why the current epoch stopped."""

        self._current_proto: Protocol | None = None
        """Current protocol being fuzzed."""

        self._current_msg: Message | None = None
        """Current message being fuzzed inside the current protocol."""

        self._current_route: Route | None = None
        """Current route in the protocol tree being fuzzed."""

        self._num_cases_actually_fuzzed: int = 0
        """Number of test cases actually fuzzed during the current run."""

        self._run_id: str | None = None
        """Unique identifier for the current fuzzing run."""

        self._run_path: Path | None = None
        """Path to the directory where findings relative to the current run will be stored."""

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

    def _restart_target(self) -> bool:
        """Restart the target system and check its liveness.

        This function attempts to restart the target system using the available monitors. After 
        restarting, it waits for a specified amount of time to allow the system to settle and 
        finally it checks the liveness of the target system using the monitors.

        Returns:
            bool: `True` if the target system was successfully restarted and is alive, `False` 
                otherwise.
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

        return restarted and is_alive

    def run(self) -> int:
        """Start to fuzz all the protocols specified.

        Returns:
            int: `0` if the fuzzing process completed successfully, `1` otherwise.
        """
        # create the findings directory for the current run
        self._run_id = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0).isoformat().replace(":", "-")
        self._run_path = self.findings_dir_path / Path(self._run_id)
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

    def _fuzz_protocol(self):
        """Fuzz all the possible routes for the current protocol."""

        self._current_epoch = 0
        self._logger.info("Fuzzing of protocol %s started",
                          self._current_proto.name)

        for path in self._current_proto:
            self._current_route = path
            self._current_epoch += 1
            self._fuzz_protocol_epoch()

        self._logger.info("Fuzzing of protocol %s ended",
                          self._current_proto.name)

    def _fuzz_protocol_epoch(self):
        """Fuzz a single epoch for the current protocol."""

        self._logger.info("Epoch #%s started", self._current_epoch)

        self._epoch_stop_reason = None
        self._epoch_cases_fuzzed = 0

        for enc in self.encoders:
            enc.reset()

        for dec in self.decoders:
            dec.reset()

        iter(self._current_route)
        self._current_msg = next(self._current_route)

        self.message_source.on_message(self._mutate, args=(self,))
        self._epoch_stop_reason = self.message_source.start(
            self.wait_time_before_epoch_end)

        self._logger.info("Epoch #%s terminated for reason: %s",
                          self._current_epoch, self._epoch_stop_reason)

    def _mutate(self, data: bytes) -> bool:
        """Callback function called on each new message received.

        This function mutates the input message based on the current protocol, message, and fuzzing status.

        Args:
            data: The input data that makes up the new message.

        Returns:
            bool: `True` if the current fuzzing epoch should stop, `False` otherwise.
        """

        to_be_fuzzed = self._current_msg == self._current_route.path[-1].dst
        if to_be_fuzzed:
            self._logger.info("Test case #%s started",
                              self._epoch_cases_fuzzed + 1)

        # apply all the decoders to the received data
        for dec in self.decoders:
            data = dec.decode(data, self._current_proto,
                              self._current_msg, to_be_fuzzed)

        if to_be_fuzzed:

            fuzzable_data = self._current_proto.parse_fuzzable(data)

            # TODO: mutate data

            data = fuzzable_data

            self._current_route.rollback()
        else:
            self._current_msg = next(self._current_route)

        # apply all the encoders to the (maybe fuzzed) data
        for enc in self.encoders:
            data = enc.encode(data, self._current_proto, self._current_msg)

        self.target.send(data)

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
                        return True

            if self._epoch_cases_fuzzed >= self.max_test_cases_per_epoch:
                self._epoch_stop_reason = "Max test cases per epoch reached"
                return True

        return False
