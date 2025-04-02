import os
import argparse
import sys
import logging
import io
import subprocess
import socket
from typing import override
from queue import Queue, ShutDown

from scapy import all as scapy

from ..agent import Agent, ExecutionContext
from ..utils.threads import EventStoppableThread, ExceptionRaiserThread
from ..utils.register import register
from ..utils.other import run_as_root
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


class SnifferThread(EventStoppableThread, ExceptionRaiserThread):
    """Thread class that sniffs packets."""

    packets: Queue
    """Packets sniffed by this thread."""

    # pylint: disable=redefined-builtin
    def __init__(self, iface: str | list[str], filter: str | None):
        super().__init__()

        self._socket = None

        self._iface = iface
        self._filter = filter
        self.packets = Queue()
        self.exception = None

    @override
    def handled_run(self):
        args = {
            'type': scapy.ETH_P_ALL,
            'iface': self._iface
        }
        if self._filter:
            args['filter'] = self._filter

        try:
            self._socket = scapy.conf.L2listen(**args)
            scapy.sniff(
                opened_socket=self._socket,
                prn=self._on_packet,
                stop_filter=self._should_stop_sniffer,
                store=0
            )
        except ShutDown:
            pass

    def _on_packet(self, packet: scapy.Packet) -> str:
        self.packets.put_nowait(packet)
        return packet.sniffed_on + ": " + packet.summary()

    def _should_stop_sniffer(self, _) -> bool:
        return self.stop_event.is_set() or self.packets.is_shutdown

    def force_close(self):
        self._socket.close()


@register(Agent)
class NetworkSnifferAgent(GrpcClientAgent):
    """Agent that sniff packets on the server."""

    # pylint: disable=useless-parent-delegation
    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                - `'iface'`: The name of the interface or a list of interface names to capture.
                - `'filter'` (optional): String specifying a filter to apply to the data being 
                    logged. See ![here](https://biot.com/capstats/bpf.html). Defaults to `None`.
                - `'restart_on_epoch'` (optional): Whether the sniffer should be started and 
                        stopped respectively at the beginning and at the end of every epoch. Defaults to `False`.
                - `'restart_on_test'` (optional): Whether the sniffer should be started and stopped 
                        respectively at the beginning and at the end of every test case or not. 
                        Defaults to `False`.
                - `'restart_on_redo'` (optional): Whether the sniffer should be restarted before 
                        re-performing a test case or not. Defaults to `False`.
                - `'restart_on_fault'` (optional): Whether the sniffer should be restarted at the 
                        end of a test case after a fault has been found or not (even if 
                        `restart_on_test` is set to `False`). Defaults to `False`.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return False

    @override
    def redo_test(self) -> bool:
        return False

    @override
    def fault_detected(self) -> bool:
        return False

    @override
    def stop_execution(self) -> bool:
        return False

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


class NetworkSnifferServerAgent(GrpcServerAgent):
    """Server agent that sniff packets on the machine.

    Note: This agent needs root privileges in order to work properly.
    """

    DEFAULT_OPTIONS: dict[str, str | list[str] | bool | None] = {
        'iface': None,
        'filter': None,
        'restart_on_epoch': False,
        'restart_on_test': False,
        'restart_on_redo': False,
        'restart_on_fault': False,
    }

    options: dict[str, str | list[str] | bool | None]
    """Options currently set on the agent."""

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._sniffer: SnifferThread | None = None
        self._fault_detected: bool = False

    @override
    def set_options(self, **kwargs):
        for key, val in kwargs.items():
            if key not in self.options:
                continue

            self.options[key] = val
            logging.info('Set %s = %s', key, val)

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self._sniffer = None
        self._fault_detected = False

    def _start_procedure(self):
        """Start the packet sniffer.

        Raises:
            AgentError: If the interface is not specified, not found, or the filter is invalid.
        """

        if self.options['iface'] is None:
            err_msg = "Interface not specified"
            logging.error(err_msg)
            raise AgentError(err_msg)

        try:
            socket.if_nametoindex(self.options['iface'])
        except OSError as e:
            err_msg = f"Interface '{self.options['iface']}' not found"
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        try:
            p: subprocess.Popen = scapy.tcpdump(flt=self.options['filter'], getproc=True)
            p.kill()

            # essential, otherwise they remains open
            if p.stdin:
                p.stdin.close()
            if p.stdout:
                p.stdout.close()
            if p.stderr:
                p.stderr.close()
        except scapy.Scapy_Exception as e:
            err_msg = f"Invalid filter '{self.options['filter']}'"
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        self._sniffer = SnifferThread(self.options['iface'], self.options['filter'])
        self._sniffer.start()

    def _stop_procedure(self):
        """Stop the packet sniffer.

        Raises:
            AgentError: If an exception occurred during the sniffer's execution.
        """

        if self._sniffer is not None:
            self._sniffer.join(timeout=0.1)
            if self._sniffer.is_alive():
                self._sniffer.force_close()

            if self._sniffer.exception is not None:
                err_msg = str(self._sniffer.exception).strip()
                logging.error(err_msg)
                raise AgentError(err_msg) from self._sniffer.exception

            self._sniffer = None

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        if self.options['restart_on_epoch'] and self._sniffer is None:
            self._start_procedure()

    @override
    def on_epoch_end(self):
        if self.options['restart_on_epoch']:
            self._stop_procedure()

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if (self.options['restart_on_test'] or self._fault_detected) and self._sniffer is None:
            self._fault_detected = False
            self._start_procedure()

    @override
    def on_test_end(self):
        if self.options['restart_on_test'] or self._fault_detected:
            self._stop_procedure()

    @override
    def on_redo(self):
        if self.options['restart_on_redo']:
            self._stop_procedure()
            self._start_procedure()

    @override
    def on_fault(self):
        self._fault_detected = self.options['restart_on_fault']

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        if self._sniffer is None:
            return []

        if self._sniffer.exception is not None:
            err_msg = str(self._sniffer.exception).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from self._sniffer.exception

        packets: list[scapy.Packet] = []
        while not self._sniffer.packets.empty():
            packets.append(self._sniffer.packets.get_nowait())

        name = f"{self.options['iface']}.pcap"
        pcap_bytes_io = io.BytesIO()

        # this is needed because wrpcap calls close() at the end
        close_fn = pcap_bytes_io.close
        pcap_bytes_io.close = lambda: None
        scapy.wrpcap(pcap_bytes_io, packets)

        pcap_bytes_io.close = close_fn
        res = [(name, pcap_bytes_io.getvalue())]
        pcap_bytes_io.close()
        return res

    @override
    def on_shutdown(self):
        self._stop_procedure()


__all__ = ['NetworkSnifferAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that sniff packets on the machine.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if os.geteuid() != 0:
        run_as_root()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    agent = NetworkSnifferServerAgent(address=args.ip, port=args.port)

    agent.serve()
