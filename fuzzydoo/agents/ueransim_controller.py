import os
import argparse
import sys
import logging
import shlex
import time
import subprocess
from dataclasses import dataclass
from collections.abc import Callable
from subprocess import CalledProcessError, CompletedProcess, Popen, PIPE
from pathlib import Path
from threading import Event
from queue import Queue, ShutDown, Full
from typing import override, IO, ClassVar

import yaml
from more_itertools import first_true

from ..agent import Agent, ExecutionContext
from ..utils.threads import EventStoppableThread, ExceptionRaiserThread, with_thread_safe_get_set
from ..utils.register import register
from ..utils.other import run_as_root
from ..protocol import ProtocolPath
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


NGAP_GNB_START = [
    {'name': 'NGSetupRequestMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'NGSetupResponseMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False}
]

NGAP_GNB_START_UE_START = NGAP_GNB_START + [
    {'name': 'InitialUEMessageMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'DownlinkNASTransportMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
    {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'DownlinkNASTransportMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
    {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'InitialContextSetupRequestMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
    {'name': 'InitialContextSetupResponseMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    {'name': 'DownlinkNASTransportMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': True},
    {'name': 'PDUSessionResourceSetupRequestMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
    {'name': 'PDUSessionResourceSetupResponseMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
]

NGAP_SUPPORTED_PATHS = [
    # ue release
    NGAP_GNB_START_UE_START + [
        {'name': 'UEContextReleaseRequestMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'UEContextReleaseCommandMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'UEContextReleaseCompleteMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    ],

    # ue deregister normal
    NGAP_GNB_START_UE_START + [
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'DownlinkNASTransportMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'UEContextReleaseCommandMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'UEContextReleaseCompleteMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    ],

    # ue deregister disable 5g
    NGAP_GNB_START_UE_START + [
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'DownlinkNASTransportMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'UEContextReleaseCommandMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'UEContextReleaseCompleteMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    ],

    # ue deregister remove sim/switch off
    NGAP_GNB_START_UE_START + [
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': True},
        {'name': 'DownlinkNASTransportMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': True},
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'UEContextReleaseCommandMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'UEContextReleaseCompleteMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    ],

    # ue pdu session release
    NGAP_GNB_START_UE_START + [
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'PDUSessionResourceReleaseCommandMessage', 'src': 'AMF', 'dst': 'NG-RAN node', 'optional': False},
        {'name': 'PDUSessionResourceReleaseResponseMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
        {'name': 'UplinkNASTransportMessage', 'src': 'NG-RAN node', 'dst': 'AMF', 'optional': False},
    ]
]

NAS_MM_UE_START = [
    {'name': 'FGMMRegistrationRequestMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    {'name': 'FGMMAuthenticationRequestMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
    {'name': 'FGMMAuthenticationResponseMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    {'name': 'FGMMSecurityModeCommandMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
    {'name': 'FGMMSecurityModeCompleteMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    {'name': 'FGMMRegistrationAcceptMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
    {'name': 'FGMMRegistrationCompleteMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    {'name': 'FGMMULNASTransportMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    {'name': 'FGMMConfigurationUpdateCommandMessage', 'src': 'AMF', 'dst': 'UE', 'optional': True},
    {'name': 'FGMMDLNASTransportMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
]

NAS_MM_SUPPORTED_PATHS = [
    # ue deregister normal
    NAS_MM_UE_START + [
        {'name': 'FGMMMODeregistrationRequestMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
        {'name': 'FGMMMODeregistrationAcceptMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
        {'name': 'FGMMRegistrationRequestMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    ],

    # ue deregister disable 5g
    NAS_MM_UE_START + [
        {'name': 'FGMMMODeregistrationRequestMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
        {'name': 'FGMMMODeregistrationAcceptMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
    ],

    # ue deregister remove sim/switch off
    NAS_MM_UE_START + [{'name': 'FGMMMODeregistrationRequestMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False}],

    # ue pdu session release
    NAS_MM_UE_START + [
        {'name': 'FGMMULNASTransportMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
        {'name': 'FGMMDLNASTransportMessage', 'src': 'AMF', 'dst': 'UE', 'optional': False},
        {'name': 'FGMMULNASTransportMessage', 'src': 'UE', 'dst': 'AMF', 'optional': False},
    ],
]

NAS_SM_UE_START = [
    {'name': 'FGSMPDUSessionEstabRequestMessage', 'src': 'UE', 'dst': 'SMF', 'optional': False},
    {'name': 'FGSMPDUSessionEstabAcceptMessage', 'src': 'SMF', 'dst': 'UE', 'optional': False},
]

NAS_SM_SUPPORTED_PATHS = [
    # ue pdu session release
    NAS_SM_UE_START + [
        {'name': 'FGSMPDUSessionReleaseRequestMessage', 'src': 'UE', 'dst': 'SMF', 'optional': False},
        {'name': 'FGSMPDUSessionReleaseCommandMessage', 'src': 'SMF', 'dst': 'UE', 'optional': False},
        {'name': 'FGSMPDUSessionReleaseCompleteMessage', 'src': 'UE', 'dst': 'SMF', 'optional': False},
    ],
]


class OutputListenerThread(EventStoppableThread):
    """Thread class that listens for output of UERANSIM tools."""

    stream: IO[bytes]
    """Stream on which this thread will listen on."""

    output: list[str]
    """Decoded output captured by this thread."""

    output_queues: list[Queue]
    """Queues where raw output will be stored."""

    def __init__(self, stream: IO[bytes], output_queues: list[Queue] | None = None):
        super().__init__()
        self.stream = stream
        self.output = []
        self.output_queues = output_queues or []

    @override
    def run(self):
        while not self.stop_event.is_set():
            line = self.stream.readline()
            if not line:
                break  # EOF reached
            decoded_line = line.decode().strip()
            self.output.append(decoded_line)
            for q in self.output_queues:
                try:
                    q.put_nowait(decoded_line)
                except (ShutDown, Full):
                    pass

        for q in self.output_queues:
            q.shutdown(True)

        self.stream.close()

    @override
    def join(self, timeout=None):
        self.stream.close()
        super().join(timeout)


class OutputWatcherThread(EventStoppableThread):
    """Thread class that watches for output of UERANSIM tools."""

    pred: Callable[[str], bool]
    """Predicate to decide whether a line correspond to a match."""

    on_match: Callable[[str], None]
    """Function executed on each new match."""

    queue: Queue
    """Input queue."""

    watch_event: Event
    """Event signaling a new match."""

    def __init__(self,
                 pred: Callable[[str], bool],
                 on_match: Callable[[str], None] = lambda _: None):
        super().__init__()

        self.pred = pred
        self.on_match = on_match

        self.queue = Queue()

        self.watch_event = Event()
        self.watch_event.clear()

    @override
    def run(self):
        while not self.stop_event.is_set():
            try:
                line = self.queue.get()
            except ShutDown:
                break

            if self.pred(line):
                self.watch_event.set()
                self.on_match(line)


class ErrorDetectorThread(OutputWatcherThread):
    """Thread class that detects errors of UERANSIM tools."""

    err_msg: str | None
    """Error message extracted from the last error line."""

    def __init__(self):
        super().__init__(self.detect_error, self.on_error)
        self.err_msg = None

    def detect_error(self, line: str) -> bool:
        """Check whether the current line contains an error message.

        Args:
            line: The line to check.

        Returns:
            bool: Whether the current line contains an error message.
        """

        return '[error]' in line

    def on_error(self, line: str):
        """Extract the error message from the given line.

        It is assumed that `self.detect_error(line) == True` holds.

        Args:
            line: The line to extract the error message from.
        """

        self.err_msg = line.split('[error]')[1].strip()


@with_thread_safe_get_set
@dataclass
class UERANSIMToolDescriptor:
    """Data structure containing some useful data related to a single UERANSIM tool."""

    name: str
    """Name of the UERANSIM tool."""

    execution_path: Path
    """Path where the UERANSIM tool's executable is placed."""

    configuration_path: Path
    """Path where the UERANSIM tool's configuration file is placed."""

    instance_number: int
    """The number of the current instance."""

    process: Popen[bytes] | None = None
    """Process descriptor for the UERANSIM tool."""

    node_name: str | None = None
    """Name of the node to use with the UERANSIM cli."""

    _n_instances: ClassVar[dict[str, int]] = {}

    def __init__(self, name: str,
                 execution_path: Path,
                 configuration_path: Path,
                 process: Popen[bytes] = None,
                 node_name: str = None):
        self.name = name
        self.execution_path = execution_path
        self.configuration_path = configuration_path
        self.process = process
        self.node_name = node_name

        self._n_instances[self.name] = self._n_instances.get(self.name, 0) + 1
        self.instance_number = self._n_instances[self.name]


class UERANSIMCli:
    """Class representing the UERANSIM cli tool."""

    @classmethod
    def run_cmd(cls, path: Path, node: str | None = None, cmd: str | None = None) -> CompletedProcess[bytes]:
        """Run the command specified using UERANSIM Command Line Interface.

        If at least one between `node` and `cmd` is not specified, this method will run the command
        to dump all the UEs and gNBs in the environment.

        Args:
            path: Path where the UERANSIM cli is located.
            node (optional): Node name of the UE/gNB to run command on behalf of. Defaults to
                `None`.
            cmd (optional): Command to run through the UERANSIM cli. Defaults to `None`.

        Returns:
            CompletedProcess[bytes]: The `CompletedProcess` instance resulted from running the
                command.

        Raises:
            AgentError: If the command execution fails.
        """

        if node is None or cmd is None:
            args = '--dump'
        else:
            args = f'{node} --exec "{cmd}"'

        cmd = f"{path} {args}"

        logging.debug("Executing command: '%s'", cmd, extra={'tool': "Cli"})
        try:
            return subprocess.run(shlex.split(cmd), stdout=PIPE,
                                  stderr=PIPE, shell=False, check=True)
        except CalledProcessError as e:
            raise AgentError(
                f"Error running UERANSIM CLI command '{cmd}': {e.stderr.decode()}") from e
        except OSError as e:
            raise AgentError(
                f"Error running UERANSIM CLI command '{cmd}': {e}") from e


class ProcessHandlerThread(EventStoppableThread, ExceptionRaiserThread):
    """Thread class that handle UERANSIM processes."""

    descriptor: UERANSIMToolDescriptor
    """The UERANSIM tool descriptor of the tool this thread handles."""

    is_success: Callable[[str], bool]
    """Predicate indicating whether the main task of the handled process is successfully executed. 
    It takes as argument a string which corresponds to a line taken from the standard output of the 
    process."""

    output_listener: OutputListenerThread
    """Output listener to attach to the handled process. Must be set by the user of this class 
    before calling `start`."""

    error_detector: ErrorDetectorThread
    """Error detector to attach to the handled process. Must be set by the user of this class 
    before calling `start`."""

    success_detector: OutputWatcherThread
    """Output watcher to attach to the handled process. Must be set by the user of this class 
    before calling `start`."""

    def __init__(self, descriptor: UERANSIMToolDescriptor, is_success: Callable[[str], bool], terminate_on_error: bool = True):
        super().__init__()

        self.descriptor = descriptor
        self.is_success = is_success
        self.output_listener = None
        self.error_detector = None
        self.success_detector = None

        self._terminate_on_error: Event = Event()
        self.terminate_on_error = terminate_on_error

    @property
    def success_event(self) -> Event | None:
        """The success event associated with this thread."""

        return self.success_detector.watch_event if self.success_detector is not None else None

    @property
    def output(self) -> list[str]:
        """The output of the UERANSIM process."""

        return self.output_listener.output if self.output_listener is not None else []

    def _retrieve_node_name(self):
        """Retrieve the node name for the UERANSIM cli from the configuration file.

        The new node name will be saved into the tool descriptor.

        Raises:
            AgentError: If an error occurs while reading the configuration file.
        """

        try:
            with open(self.descriptor.configuration_path, 'r', encoding='utf8') as f:
                configs = yaml.safe_load(f)
        except (FileNotFoundError, PermissionError, yaml.YAMLError, IOError) as e:
            raise AgentError(f"Error reading configuration file: {e}") from e

        if 'supi' in configs:
            # it's a UE
            node_name = configs['supi']
        else:
            # it's a gNB
            node_name = (f"UERANSIM-gnb-{configs['mcc']}-"
                         f"{configs['mnc']}-{self.descriptor.instance_number}")

        self.descriptor.node_name = node_name

    def _start_in_bg(self):
        """Start the tool in background as a subprocess.

        Raises:
            AgentError: If an error occurs while starting the tool.
        """

        cmd = (f"{self.descriptor.execution_path} "
               f"--config {self.descriptor.configuration_path}")
        try:
            self.descriptor.process = Popen(shlex.split(cmd), shell=False,  # bufsize=1,
                                            close_fds=True, stdout=PIPE, stderr=PIPE)
        except OSError as e:
            raise AgentError(
                f"Error starting {self.descriptor.name}: {e}") from e

    def _stop_in_bg(self):
        """Stop the tool running in the background.

        If the tool is not running, nothing will be done.
        """

        if self.descriptor.process is not None:
            self.descriptor.process.terminate()
            time.sleep(0.5)
            if self.descriptor.process.poll() is None:
                self.descriptor.process.kill()

    def _cleanup(self, logger: OutputWatcherThread):
        """Perform some cleanup operations before joining the thread.

        Args:
            logger: The logger thread used during the thread execution.
        """

        self._stop_in_bg()

        self.output_listener.join()
        logger.join()
        self.success_detector.join()
        self.error_detector.join()

    @property
    def terminate_on_error(self) -> bool:
        """Whether to terminate the process if an error is detected."""

        return self._terminate_on_error.is_set()

    @terminate_on_error.setter
    def terminate_on_error(self, value: bool):
        if value:
            self._terminate_on_error.set()
        else:
            self._terminate_on_error.clear()

    @override
    def handled_run(self):
        try:
            self._start_in_bg()
            self._retrieve_node_name()
        except AgentError as e:
            self.is_error_recoverable = False
            self._stop_in_bg()
            raise e

        self.output_listener = OutputListenerThread(
            self.descriptor.process.stdout)

        self.error_detector = ErrorDetectorThread()
        self.output_listener.output_queues.append(self.error_detector.queue)

        self.success_detector = OutputWatcherThread(self.is_success)
        self.output_listener.output_queues.append(self.success_detector.queue)

        # for logging
        output_logger = OutputWatcherThread(
            pred=(lambda _: True),
            on_match=(lambda line: logging.debug('%s', line, extra={'tool': self.descriptor.name})))
        self.output_listener.output_queues.append(output_logger.queue)

        output_logger.start()
        self.success_detector.start()
        self.error_detector.start()
        self.output_listener.start()

        while not self.stop_event.is_set():
            if self.error_detector.watch_event.is_set() and self.terminate_on_error:
                self._cleanup(output_logger)
                self.is_error_recoverable = True
                raise AgentError(self.error_detector.err_msg)

            if self.descriptor.process.poll() is not None:
                self._cleanup(output_logger)
                self.is_error_recoverable = True
                raise AgentError(f"{self.descriptor.name} exited prematurely with "
                                 f"return code '{self.descriptor.process.returncode}'")

            time.sleep(0.1)

        self._cleanup(output_logger)


class OrchestratorThread(EventStoppableThread, ExceptionRaiserThread):
    """Thread class that orchestrates the gNB and UE starting and monitoring operations."""

    gnb_handler: ProcessHandlerThread
    """Handler for UERANSIM's gNB process."""

    ue_handler: ProcessHandlerThread
    """Handler for UERANSIM's UE process."""

    cli_path: Path
    """Path to the UERANSIM CLI executable."""

    also_start_ue: bool
    """Whether to start also the UE process or not."""

    also_exec_cli: bool
    """Whether to execute also some CLI command or not."""

    protocol: str
    """The name of the protocol being fuzzed."""

    protocol_path_idx: int
    """The index of the path currently being fuzzed in `-PROTOCOL-_SUPPORTED_PATHS`."""

    def __init__(self, gnb_descriptor: UERANSIMToolDescriptor,
                 ue_descriptor: UERANSIMToolDescriptor,
                 cli_path: Path,
                 protocol: str,
                 protocol_path_idx: int,
                 also_start_ue: bool = False,
                 terminate_on_error: bool = True,
                 also_exec_cli: bool = False):
        super().__init__()

        self.gnb_handler = ProcessHandlerThread(
            gnb_descriptor,
            lambda line: "NG Setup procedure is successful" in line,
            terminate_on_error=terminate_on_error)
        self.ue_handler = ProcessHandlerThread(
            ue_descriptor,
            lambda line: "PDU Session establishment is successful" in line,
            terminate_on_error=terminate_on_error)
        self.cli_path = cli_path

        self.also_start_ue = also_start_ue
        self.also_exec_cli = also_exec_cli
        self._terminate_on_error: Event = Event()
        self.terminate_on_error = terminate_on_error

        self.protocol = protocol
        self.protocol_path_idx = protocol_path_idx

    def _path_idx_to_cmd_idx(self) -> int | None:
        """Map the given path index to the corresponding cli command index."""

        match self.protocol:
            case 'NGAP':
                return self.protocol_path_idx
            case 'NAS-MM':
                return self.protocol_path_idx + 1
            case 'NAS-SM':
                return 4
            case _:
                return None

    def _exec_cli_on_path_idx(self):
        """Execute the UERANSIM cli command that corresponds to the given path index.

        Raises:
            AgentError: If some error occurred during the execution of the cli command.
        """

        match self._path_idx_to_cmd_idx():
            case 0:
                # nr-cli GNB-NODE-NAME --exec "ue-list"
                res = UERANSIMCli.run_cmd(self.cli_path,
                                          self.gnb_handler.descriptor.node_name,
                                          "ue-list")

                ue_id = first_true(
                    res.stdout.decode().split('\n'),
                    default=None, pred=lambda line: line[0] == '-')

                if ue_id is None:
                    raise AgentError(
                        f"Error getting gNB's UE ID: {res.stderr.decode()}")

                ue_id = ue_id.split(': ')[1].strip()

                # nr-cli GNB-NODE-NAME --exec "ue-release UE-ID"
                UERANSIMCli.run_cmd(self.cli_path,
                                    self.gnb_handler.descriptor.node_name,
                                    f"ue-release {ue_id}")

            case 1:
                # nr-cli UE-NODE-NAME --exec "deregister normal"
                UERANSIMCli.run_cmd(self.cli_path,
                                    self.ue_handler.descriptor.node_name,
                                    "deregister normal")
            case 2:
                # nr-cli UE-NODE-NAME --exec "deregister disable-5g"
                UERANSIMCli.run_cmd(self.cli_path,
                                    self.ue_handler.descriptor.node_name,
                                    "deregister disable-5g")
            case 3:
                # nr-cli UE-NODE-NAME --exec "deregister remove-sim"
                UERANSIMCli.run_cmd(self.cli_path,
                                    self.ue_handler.descriptor.node_name,
                                    "deregister remove-sim")
            case 4:
                # nr-cli UE-NODE-NAME --exec "ps-list"
                res = UERANSIMCli.run_cmd(self.cli_path,
                                          self.ue_handler.descriptor.node_name,
                                          "ps-list")
                pdu_session_id = first_true(
                    res.stdout.decode().split('\n'),
                    default=None, pred=lambda line: line.startswith('PDU Session'))

                if pdu_session_id is None:
                    raise AgentError(f"Error getting PDU session ID: {res.stderr.decode()}")

                # the line is "PDU Session1:\n" for session with id 1
                pdu_session_id = pdu_session_id.split('Session')[1].split(':')[0]

                # nr-cli UE-NODE-NAME --exec "ps-release PDU-SESSION-ID"
                UERANSIMCli.run_cmd(self.cli_path,
                                    self.ue_handler.descriptor.node_name,
                                    f"ps-release {pdu_session_id}")

            case _:
                pass

    @property
    def gnb_output(self) -> list[str]:
        """The stdout of gNB."""

        return self.gnb_handler.output

    @property
    def ue_output(self) -> list[str]:
        """The stdout of UE."""

        return self.ue_handler.output

    @property
    def terminate_on_error(self) -> bool:
        """Whether to terminate the orchestrator thread if an error occurs or not."""

        return self._terminate_on_error.is_set()

    @terminate_on_error.setter
    def terminate_on_error(self, value: bool):
        if value:
            self._terminate_on_error.set()
        else:
            self._terminate_on_error.clear()

    def _cleanup(self):
        """Perform some cleanup operations before joining the thread."""

        if self.ue_handler.ident is not None:
            self.ue_handler.join()
            logging.info('Stopped',
                         extra={'tool': self.ue_handler.descriptor.name})
        if self.gnb_handler.ident is not None:
            self.gnb_handler.join()
            logging.info('Stopped',
                         extra={'tool': self.gnb_handler.descriptor.name})

    @override
    def handled_run(self):
        self.gnb_handler.start()
        logging.info('Started',
                     extra={'tool': self.gnb_handler.descriptor.name})

        is_cli_executed = False
        while not self.stop_event.is_set():
            if self.ue_handler.is_error_occurred and self.terminate_on_error:
                e = self.ue_handler.exception
                self.is_error_recoverable = self.ue_handler.is_error_recoverable
                if self.is_error_recoverable:
                    logging.warning('%s', str(e), extra={'tool': self.ue_handler.descriptor.name})
                else:
                    logging.error('%s', str(e), extra={'tool': self.ue_handler.descriptor.name})
                raise e

            if self.gnb_handler.is_error_occurred and self.terminate_on_error:
                e = self.gnb_handler.exception
                self.is_error_recoverable = self.gnb_handler.is_error_recoverable
                if self.is_error_recoverable:
                    logging.warning('%s', str(e),
                                    extra={'tool': self.gnb_handler.descriptor.name})
                else:
                    logging.error('%s', str(e),
                                  extra={'tool': self.gnb_handler.descriptor.name})
                raise e

            if not self.ue_handler.is_alive():
                if self.also_start_ue \
                        and self.gnb_handler.success_event is not None \
                        and self.gnb_handler.success_event.is_set():
                    self.ue_handler.start()
                    logging.info('Started', extra={'tool': self.ue_handler.descriptor.name})
            elif self.also_exec_cli \
                    and not is_cli_executed \
                    and self.ue_handler.success_event is not None \
                    and self.ue_handler.success_event.is_set():
                try:
                    self._exec_cli_on_path_idx()
                    is_cli_executed = True
                except AgentError as e:
                    logging.warning('%s', str(e), extra={'tool': 'cli'})
                    self.is_error_recoverable = True
                    raise e

            time.sleep(0.1)

    @override
    def join(self, timeout=None):
        super().join(timeout)
        self._cleanup()


@register(Agent)
class UERANSIMControllerAgent(GrpcClientAgent):
    """Agent that controls the UERANSIM tools."""

    def __init__(self, **kwargs):
        if 'wait_start_time' not in kwargs:
            kwargs['wait_start_time'] = 1.0
        super().__init__(**kwargs)

    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                - `'gnb'` (optional): A dictionary with the following key-value pairs:
                    - `'exe_path'` (optional): A string representing the remote path where the
                        executable program to be used for the gnb is located. Defaults to
                        `'./nr-gnb'`.
                    - `'config_path'` (optional): A string representing the remote path where the
                        configuration file to be used for the gnb is located. Defaults to
                        `'./gnb.yaml'`.
                    - `'direct_config_path'` (optional): A string representing the remote path 
                        where the configuration file to be used for the gnb is located. This 
                        configuration file must be written such that the gnb doesn't connect to a 
                        proxy, but connects directly to the amf. Defaults to `'./gnb.yaml'`.
                - `'ue'` (optional): A dictionary with the following key-value pairs:
                    - `'exe_path'` (optional): A string representing the remote path where the
                        executable program to be used for the ue is located. Defaults to
                        `'./nr-ue'`.
                    - `'config_path'` (optional): A string representing the remote path where the
                        configuration file to be used for the gnb is located. Defaults to
                        `'./ue.yaml'`.
                - `'cli_path'` (optional): A string representing the remote path where the 
                    executable program to be used for the cli is located. Defaults to `'./nr-cli'`.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method
                `stop_execution` is called.
        """

        super().set_options(**kwargs)

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        return

    @override
    def on_epoch_end(self):
        return

    @override
    def on_fault(self):
        return

    @override
    def start(self, pub_id: int):
        return

    @override
    def stop(self, pub_id: int):
        return

    @override
    def send(self, pub_id: int, data: bytes):
        return

    @override
    def receive(self, pub_id: int) -> bytes:
        return b""

    @override
    def data_available(self, pub_id: int) -> bool:
        return False


class UERANSIMControllerServerAgent(GrpcServerAgent):
    """Server agent that controls the UERANSIM tools.

    Note: This agent needs root privileges in order to work properly.
    """

    _SUPPORTED_PROTOCOLS: list[str] = ['NGAP', 'NAS-MM', 'NAS-SM']

    DEFAULT_OPTIONS: dict[str, Path] = {
        'gnb_exe_path': Path('./nr-gnb'),
        'gnb_config_path': Path('./gnb.yaml'),
        'gnb_direct_config_path': Path('./gnb.yaml'),
        'ue_exe_path': Path('./nr-ue'),
        'ue_config_path': Path('./ue.yaml'),
        'cli_exe_path': Path('./nr-cli'),
    }

    options: dict[str, Path]
    """Options currently set on the agent."""

    gnb: UERANSIMToolDescriptor | None
    """The UERANSIM tool descriptor for gNB."""

    ue: UERANSIMToolDescriptor | None
    """The UERANSIM tool descriptor for UE."""

    orchestrator: OrchestratorThread | None
    """The orchestrator thread that will be used during execution."""

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self.gnb = None
        self.ue = None
        self.orchestrator = None

        self._is_delay_mutation: bool = False
        self._last_exception: Exception | None = None
        self._is_recoverable: bool = True

    def _is_subpath(self, path: list[dict[str, str | bool]], subpath: ProtocolPath | list[str]) -> bool:
        """Check if `subpath` is a subpath of `path`.

        Args:
            path: List of message records representing a path.
            subpath: List of names or `ProtocolPath` instance representing the path to be checked.

        Returns:
            bool: `True` if `subpath` is a subpath of `path`, `False` otherwise.
        """

        if isinstance(subpath, ProtocolPath):
            subpath = subpath.names

        if len(path) < len(subpath):
            return False

        for m1, m2 in zip(path, subpath):
            if m1['name'] != m2:
                return False

        return True

    def _get_subpath_idx(self, protocol: str, subpath: ProtocolPath) -> int | None:
        """Get the index of the supported path whose `subpath` is a subpath.

        Args:
            protocol: The name of the protocol.
            subpath: Subpath whose index will be retrieved.

        Returns:
            int | None: The index of the supported path, or `None` if the path is not supported.
        """

        if protocol == "NGAP":
            supported_paths = NGAP_SUPPORTED_PATHS
        elif protocol == "NAS-MM":
            supported_paths = NAS_MM_SUPPORTED_PATHS
        elif protocol == "NAS-SM":
            supported_paths = NAS_SM_SUPPORTED_PATHS
        else:
            return None

        names = subpath.names
        for i, path in enumerate(supported_paths):
            if self._is_subpath(path, names):
                return i

        return None

    @override
    def set_options(self, **kwargs):
        if 'gnb' in kwargs:
            gnb_configs = kwargs['gnb']
            if 'exe_path' in gnb_configs:
                self.options['gnb_exe_path'] = Path(gnb_configs['exe_path'])
                logging.info('Set gnb[%s] = %s', 'execution_path', self.options['gnb_exe_path'])
            if 'config_path' in gnb_configs:
                self.options['gnb_config_path'] = Path(gnb_configs['config_path'])
                logging.info('Set gnb[%s] = %s',
                             'configuration_path', self.options['gnb_config_path'])
            if 'direct_config_path' in gnb_configs:
                self.options['gnb_direct_config_path'] = Path(gnb_configs['direct_config_path'])
                logging.info('Set gnb[%s] = %s',
                             'direct_configuration_path', self.options['gnb_direct_config_path'])

        if 'ue' in kwargs:
            ue_configs = kwargs['ue']
            if 'exe_path' in ue_configs:
                self.options['ue_exe_path'] = Path(ue_configs['exe_path'])
                logging.info('Set ue[%s] = %s', 'execution_path', self.options['ue_exe_path'])
            if 'config_path' in ue_configs:
                self.options['ue_config_path'] = Path(ue_configs['config_path'])
                logging.info('Set ue[%s] = %s', 'configuration_path', self.options['ue_config_path'])

        if 'cli_path' in kwargs:
            self.options['cli_exe_path'] = Path(kwargs['cli_path'])
            logging.info('Set %s = %s', 'cli_path', self.options['cli_exe_path'])

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self.gnb = None
        self.ue = None
        self.orchestrator = None
        self._last_exception = None
        self._is_recoverable = True

    @override
    def get_supported_paths(self, protocol: str) -> list[list[dict[str, str | bool]]]:
        match protocol:
            case 'NGAP':
                return NGAP_SUPPORTED_PATHS
            case 'NAS-MM':
                return NAS_MM_SUPPORTED_PATHS
            case 'NAS-SM':
                return NAS_SM_SUPPORTED_PATHS
            case _:
                return []

    @override
    def on_test_start(self, ctx: ExecutionContext):
        self._last_exception = None
        self._is_recoverable = True

        if ctx.protocol_name not in self._SUPPORTED_PROTOCOLS:
            return

        subpath_idx = self._get_subpath_idx(ctx.protocol_name, ctx.path)
        if subpath_idx is None:
            msg = f"Unsupported path: {".".join(ctx.path.names)}"
            logging.error(msg)
            raise AgentError(msg)

        self._is_delay_mutation = ctx.mutator is not None and ctx.mutator == "DelayedMessageMutator"

        self.gnb = UERANSIMToolDescriptor(
            'gNB', self.options['gnb_exe_path'], self.options['gnb_config_path'])

        self.ue = UERANSIMToolDescriptor(
            'UE', self.options['ue_exe_path'], self.options['ue_config_path'])

        self.orchestrator = OrchestratorThread(
            self.gnb, self.ue, self.options['cli_exe_path'], ctx.protocol_name, subpath_idx)

        path_len = len(ctx.path.names)
        if ctx.protocol_name == 'NGAP':
            self.orchestrator.also_start_ue = path_len > len(NGAP_GNB_START)
            self.orchestrator.also_exec_cli = path_len > len(NGAP_GNB_START_UE_START)
        else:
            self.orchestrator.also_start_ue = True
            if ctx.protocol_name == 'NAS-MM':
                self.orchestrator.also_exec_cli = path_len > len(NAS_MM_UE_START)
            elif ctx.protocol_name == 'NAS-SM':
                self.orchestrator.also_exec_cli = path_len > len(NAS_SM_UE_START)

        self.orchestrator.start()

    @override
    def on_test_end(self):
        if self.orchestrator is None:
            return

        self.orchestrator.join()
        self.orchestrator = None

        if self._last_exception is not None \
                and (not self._is_delay_mutation
                     or "no response from the network" not in str(self._last_exception)) \
                and "protocol/semantic-error" not in str(self._last_exception) \
                and "Error indication received" not in str(self._last_exception):
            raise self._last_exception

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        res = []

        stream = "".join(self.orchestrator.gnb_output)
        record_name = self.gnb.name + ".out.txt"
        res.append((record_name, stream.encode()))

        if self.orchestrator.also_start_ue:
            stream = "".join(self.orchestrator.ue_output)
            record_name = self.ue.name + ".out.txt"
            res.append((record_name, stream.encode()))

        return res

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return ctx.protocol_name not in self._SUPPORTED_PROTOCOLS \
            or self._get_subpath_idx(ctx.protocol_name, ctx.path) is None

    @override
    def redo_test(self) -> bool:
        # in case we are delaying messages, ignore errors related to missing responses
        if self._is_delay_mutation \
                and self._last_exception is not None \
                and "no response from the network" in str(self._last_exception):
            return False

        # ignore error indications received
        if self._last_exception is not None \
                and ("protocol/semantic-error" in str(self._last_exception)
                     or "Error indication received" in str(self._last_exception)):
            return False

        return self._last_exception is not None and self._is_recoverable

    @override
    def on_redo(self):
        # for this problem (https://github.com/aligungr/UERANSIM/issues/320) sometimes a genuine
        # attempt is needed so that UERANSIM can make the core network use the right method to
        # calculate the SQN

        if self.orchestrator is not None:
            self.orchestrator.join()

        gnb = UERANSIMToolDescriptor(
            'gNB', self.options['gnb_exe_path'], self.options['gnb_direct_config_path'])

        ue = UERANSIMToolDescriptor(
            'UE', self.options['ue_exe_path'], self.options['ue_config_path'])

        orchestrator = OrchestratorThread(
            gnb,
            ue,
            self.options['cli_exe_path'],
            self.orchestrator.protocol,
            self.orchestrator.protocol_path_idx,
            also_start_ue=True,
            terminate_on_error=False
        )

        orchestrator.start()
        start = time.time()
        while True:
            if orchestrator.ue_handler.is_alive() \
                    and orchestrator.ue_handler.success_event is not None \
                    and orchestrator.ue_handler.success_event.is_set():
                break

            if time.time() - start >= 60:
                break

            time.sleep(0.1)

        orchestrator.join()

    @override
    def fault_detected(self) -> bool:
        # since this is called before redo_test, but after the message exchange is terminated, we
        # can signal the orchestrator to ignore future errors

        self._last_exception = self.orchestrator.exception
        self._is_recoverable = self.orchestrator.is_error_recoverable

        self.orchestrator.terminate_on_error = False

        return False

    @override
    def stop_execution(self) -> bool:
        # in case we are delaying messages, ignore errors related to missing responses
        if self._is_delay_mutation \
                and self._last_exception is not None \
                and "no response from the network" in str(self._last_exception):
            return False

        # ignore error indications received
        if self._last_exception is not None \
                and ("protocol/semantic-error" in str(self._last_exception)
                     or "Error indication received" in str(self._last_exception)):
            return False

        return self._last_exception is not None and not self._is_recoverable


__all__ = ['UERANSIMControllerAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that controls the UERANSIM tools.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if os.geteuid() != 0:
        run_as_root()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="[%(tool)s][%(levelname)s] - %(message)s")

    class DefaultToolFilter(logging.Filter):
        @override
        def filter(self, record):
            if not hasattr(record, 'tool'):
                record.tool = "Server"
            return True

    logging.getLogger("root").addFilter(DefaultToolFilter())

    agent = UERANSIMControllerServerAgent(address=args.ip, port=args.port)

    agent.serve()
