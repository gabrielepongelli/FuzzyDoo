import logging
import io
from typing import override

import scapy.all as scapy

from ..agent import Agent, AgentError, ExecutionContext
from ..utils.threads import EventStoppableThread
from ..utils.register import register
from .grpc_agent import GrpcClientAgent, GrpcServerAgent


class SnifferThread(EventStoppableThread):
    """Thread class that sniffs packets."""

    # pylint: disable=redefined-builtin
    def __init__(self, iface: str | list[str], filter: str | None):
        super().__init__()

        self._socket = None

        self._iface = iface
        self._filter = filter
        self.packets: scapy.PacketList | None = None
        self.exception: Exception | None = None

    @override
    def run(self):
        args = {
            'type': scapy.ETH_P_ALL,
            'iface': self._iface
        }
        if self._filter:
            args['filter'] = self._filter

        try:
            self._socket = scapy.conf.L2listen(**args)
            self.packets = scapy.sniff(
                opened_socket=self._socket,
                prn=lambda x: x.sniffed_on+": "+x.summary(),
                stop_filter=self._should_stop_sniffer
            )
        except scapy.Scapy_Exception as e:
            self.exception = e

    def _should_stop_sniffer(self, _):
        return self.stop_event.is_set()

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
                'iface' (optional): The name of the interface or a list of interface names to 
                    capture. Defaults to `"any"`.
                'filter' (optional): String specifying a filter to apply to the data being logged. 
                    See https://biot.com/capstats/bpf.html. Defaults to `None`.

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
    def on_fault(self):
        return

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

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self._iface: str | list[str] = kwargs.get('iface', 'any')
        self._filter: str | None = kwargs.get('filter', None)
        self._sniffer: SnifferThread | None = None
        self._packets: scapy.PacketList | None = None

    @override
    def set_options(self, **kwargs):
        if 'iface' in kwargs:
            self._iface = kwargs['iface']
            logging.info('Set %s = %s', 'iface',
                         self._iface)

        if 'filter' in kwargs:
            self._filter = kwargs['filter']
            logging.info('Set %s = %s', 'filter', self._filter)

    @override
    def on_test_start(self, ctx: ExecutionContext):
        self._packets = None
        self._sniffer = SnifferThread(self._iface, self._filter)
        self._sniffer.start()

    @override
    def on_test_end(self):
        if self._sniffer is not None:
            self._sniffer.join()
            if self._sniffer.is_alive():
                self._sniffer.force_close()

            if self._sniffer.exception is not None:
                err_msg = str(self._sniffer.exception).strip()
                logging.error(err_msg)
                raise AgentError(err_msg) from self._sniffer.exception

            self._packets = self._sniffer.packets
            self._sniffer = None

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        if self._packets is None:
            return []

        name = f"{self._iface}.pcap"
        pcap_bytes_io = io.BytesIO()

        # this is needed because wrpcap calls close() at the end
        close_fn = pcap_bytes_io.close
        pcap_bytes_io.close = lambda: None
        scapy.wrpcap(pcap_bytes_io, self._packets)

        pcap_bytes_io.close = close_fn
        res = [(name, pcap_bytes_io.getvalue())]
        pcap_bytes_io.close()
        return res

    @override
    def on_shutdown(self):
        if self._sniffer is not None:
            self._sniffer.join()
            if self._sniffer.is_alive():
                self._sniffer.force_close()

            if self._sniffer.exception is not None:
                err_msg = str(self._sniffer.exception).strip()
                logging.error(err_msg)
                raise AgentError(err_msg) from self._sniffer.exception


def main():
    import os
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Agent that sniff packets on the machine.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write(
            "You need root permissions to run this script. To solve this problem execute this script like this:\n\n")
        sys.stderr.write("\tsudo $(which pcap-logger)\n\n")
        sys.exit(1)

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG,
                        format="[%(levelname)s] - %(message)s")

    agent = NetworkSnifferServerAgent(address=args.ip, port=args.port)

    agent.serve()
