import logging
import socket
import time
from queue import Empty, Queue, ShutDown
from typing import cast, override
from select import select

import sctp

from ..publisher import Publisher, PublisherOperationError
from ..agent import Agent, ExecutionContext, AgentError
from ..utils.threads import EventStoppableThread, ExceptionRaiserThread
from ..utils.register import register
from .grpc_agent import GrpcClientAgent, GrpcServerAgent


RECV_BUFF_LEN = 4096
SELECT_TIMEOUT = 0.1

PUBLISHER_SOURCE_ID = 1
PUBLISHER_SOURCE_NAME = 'source'
PUBLISHER_TARGET_ID = 2
PUBLISHER_TARGET_NAME = 'target'


# since sctp.sctpsocket is not well type-hinted, in this way we can have correct type hints also
# for the standard socket.socket methods
SctpSocketT = sctp.sctpsocket | socket.socket


class EndpointReceiverThread(EventStoppableThread, ExceptionRaiserThread):
    """A thread class responsible for receiving data from an SCTP socket.

    This class extends `EventStoppableThread` and `ExceptionRaiserThread` to provide controlled 
    execution and error handling capabilities. It continuously reads data from the assigned SCTP 
    socket and places it into a queue for further processing.

    Attributes:
        socket: The SCTP socket from which data will be read.
        queue: A thread-safe queue where received data packets are stored.
    """

    def __init__(self, sock: SctpSocketT):
        """Initialize a new `EndpointReceiverThread` instance.

        Args:
            sock: The SCTP socket from which data will be read.
        """

        super().__init__()

        self.socket: SctpSocketT = sock
        """The SCTP socket from which data will be read."""

        self.queue: Queue = Queue()
        """A thread-safe queue where received data packets are stored."""

    def handled_run(self):
        """The main execution method of the thread.

        This method continuously receives data from the SCTP socket and puts it in the queue.
        It runs until one of the following conditions is met:
        1. The socket is closed.
        2. The `stop_event` event is set.
        3. The queue is closed.
        4. An error is encountered while receiving data.

        Raises:
            PublisherOperationError: If an error occurs while receiving data from the socket.
        """

        while not self.stop_event.is_set():
            if self.socket.fileno() == -1:
                break

            ready, _, _ = select([self.socket], [], [], SELECT_TIMEOUT)
            if ready:
                try:
                    _, _, data, _ = self.socket.sctp_recv(RECV_BUFF_LEN)
                except (TimeoutError, ConnectionError) as e:
                    self.queue.shutdown(True)
                    self.is_error_recoverable = True
                    raise PublisherOperationError(
                        f"Error while receiving data: {e}") from e
                except OSError:
                    pass
                else:
                    if not data:
                        break  # EOF reached

                    try:
                        self.queue.put_nowait(data)
                    except ShutDown:
                        break

        self.queue.shutdown(True)


class EndpointSenderThread(EventStoppableThread, ExceptionRaiserThread):
    """A thread class responsible for sending data through an SCTP socket.

    This class extends `EventStoppableThread` and `ExceptionRaiserThread` to provide controlled 
    execution and error handling capabilities. It continuously takes data from a queue and sends it 
    through the assigned SCTP socket.

    Attributes:
        socket: The SCTP socket through which data will be sent.
        queue: A thread-safe queue from which data packets to be sent are taken.
    """

    def __init__(self, sock: SctpSocketT):
        """Initialize a new `EndpointSenderThread` instance.

        Args:
            sock: The SCTP socket through which data will be sent.
        """

        super().__init__()

        self.socket: SctpSocketT = sock
        """The SCTP socket through which data will be sent."""

        self.queue: Queue = Queue()
        """A thread-safe queue from which data packets to be sent are taken."""

    def handled_run(self):
        """The main execution method of the thread.

        This method continuously takes data from the queue and sends it through the SCTP socket.
        It runs until one of the following conditions is met:
        1. The `stop_event` event is set.
        2. The queue is closed.
        3. The socket is closed.
        4. An error is encountered while sending data.

        Raises:
            PublisherOperationError: If an error occurs while sending data through the socket.
        """

        while not self.stop_event.is_set():
            try:
                data = self.queue.get()
            except ShutDown:
                break

            if self.socket.fileno() == -1:
                break

            try:
                self.socket.sctp_send(data, ppid=socket.ntohl(60))
            except OSError as e:
                self.queue.shutdown(True)
                self.is_error_recoverable = True
                raise PublisherOperationError(
                    f"Error while sending data: {e}") from e

        self.queue.shutdown(True)

    @override
    def join(self, timeout: float | None = None):
        """Wait for the thread to complete its execution.

        This method overrides the standard join method to ensure that the queue
        is properly shut down before joining the thread. In this way, the main execution method 
        will exit from the blocking method `self.queue.get()`.

        Args:
            timeout (optional): The maximum time to wait for the thread to complete. If `None`, 
                wait indefinitely. Defaults to `None`.
        """

        self.queue.shutdown(True)
        super().join(timeout)


class ProxyEndpoint(Publisher):
    """A class representing one endpoint of the SCTP proxy.

    This class handles the arrival and delivery of data from one endpoint of the SCTP proxy.

    Attributes:
        socket: The SCTP socket for this endpoint.
        is_error_recoverable: Whether the error, if any, is recoverable or not.
    """

    def __init__(self, name: str, sock: SctpSocketT | None = None):
        """Initialize a `ProxyEndpoint` instance.

        Parameters:
            name: The name of this entpoint.
            socket (optional): The SCTP socket for this endpoint. Defaults to `None`.
        """

        self.name: str = name
        """Name of this entpoint."""

        self.socket: SctpSocketT | None = sock
        """SCTP socket for this endpoint."""

        self._sender: EndpointSenderThread | None = None
        self._receiver: EndpointReceiverThread | None = None

        self.is_error_recoverable: bool = True
        """Whether the error, if any, is recoverable or not."""

    @override
    def start(self):
        """Start the threads responsible for sending/receiving data form the socket.

        You need to set the `socket` attribute before calling this method, otherwise an 
        exception will be raised.

        Raises:
            PublisherOperationError: If the `socket` attribute is not set.
        """

        if self.socket is None:
            msg = 'No socket provided'
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = False
            raise PublisherOperationError(msg)

        if self.is_running:
            return

        self._sender = EndpointSenderThread(self.socket)
        self._receiver = EndpointReceiverThread(self.socket)

        self._sender.start()
        self._receiver.start()

        logging.info('Endpoint started', extra={'entity': self.name})

    @override
    def stop(self):
        """Stop the threads responsible for sending/receiving data form the socket.

        This will not close the socket, so that the connection can be recovered later.

        Raises:
            PublisherOperationError: If an error occurs while stopping the threads.
        """

        if self._sender is not None and self._sender.is_alive():
            self._sender.join()
        if self._receiver is not None and self._receiver.is_alive():
            self._receiver.join()

        logging.info('Endpoint stopped', extra={'entity': self.name})

        if self._sender and self._sender.is_error_occurred:
            msg = str(self._sender.exception)
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = self._sender.is_error_recoverable
            raise PublisherOperationError(msg)

        if self._receiver and self._receiver.is_error_occurred:
            msg = str(self._receiver.exception)
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = self._receiver.is_error_recoverable
            raise PublisherOperationError(msg)

    @property
    def is_running(self) -> bool:
        """Check if the current endpoint is running."""

        return self._sender is not None \
            and self._receiver is not None \
            and self._sender.is_alive() \
            and self._receiver.is_alive()

    @override
    def send(self, data: bytes):
        """Send some data to the endpoint.

        Args:
            data: The data to be sent.

        Raises:
            PublisherOperationError: If the endpoint is not running or if an error occurs while 
                sending the data.
        """

        if not self.is_running:
            msg = "The endpoint is not running"
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = True
            raise PublisherOperationError(msg)

        self._sender.queue.put(data)
        if self._sender.is_error_occurred:
            msg = str(self._sender.exception)
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = self._sender.is_error_recoverable
            raise PublisherOperationError(msg)

    @override
    def receive(self) -> bytes:
        """Receive some data from the endpoint.

        Returns:
            bytes: The received data. If no data is available (see `data_available`) then `b""` is 
                returned.

        Raises:
            PublisherOperationError: If the endpoint is not running or if an error occurs while 
                receiving the data.
        """

        if not self.is_running:
            msg = "The endpoint is not running"
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = True
            raise PublisherOperationError(msg)

        if self._receiver.is_error_occurred:
            msg = str(self._receiver.exception)
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = self._receiver.is_error_recoverable
            raise PublisherOperationError(msg)

        try:
            return self._receiver.queue.get_nowait()
        except Empty:
            return b''

    @override
    def data_available(self) -> bool:
        """Check if there is any data available for reading.

        Returns:
            bool: `True` if there is data available, `False` otherwise.

        Raises:
            PublisherOperationError: If the endpoint is not running.
        """

        if not self.is_running:
            msg = "The endpoint is not running"
            logging.error(msg, extra={'entity': self.name})
            self.is_error_recoverable = True
            raise PublisherOperationError(msg)

        return not self._receiver.queue.empty()

    def __hash__(self) -> int:
        return hash(tuple(self.name, self.socket.fileno()))


class SctpProxy(EventStoppableThread, ExceptionRaiserThread):
    """A class representing an SCTP proxy for forwarding data between two SCTP endpoints.

    It allows for the forwarding of data between two SCTP endpoints, enabling the capture and 
    manipulation of SCTP packets. It can be started and stopped programmatically using the 
    `start()` and `stop()` methods, respectively.

    Attributes:
        listen_ip: The IP address where the proxy will listen for incoming connections.
        listen_port: The port number where the proxy will listen for incoming connections.
        forward_from_ip: The IP address from which the proxy will forward data.
        forward_to_ip: The IP address to which the proxy will forward data.
        forward_to_port: The port number to which the proxy will forward data.
    """

    def __init__(self,
                 listen_ip: str | None = None,
                 listen_port: int | None = None,
                 forward_from_ip: str | None = None,
                 forward_to_ip: str | None = None,
                 forward_to_port: int | None = None):
        """Initializes an SCTP proxy instance.

        Args:
            listen_ip (optional): The IP address where the proxy will listen for incoming 
                connections. Defaults to `None`.
            listen_port (optional): The port number where the proxy will listen for incoming 
                connections. Defaults to `None`.
            forward_from_ip (optional): The IP address from which the proxy will forward data. 
                Defaults to `None`.
            forward_to_ip (optional): The IP address to which the proxy will forward data. Defaults 
                to `None`.
            forward_to_port (optional): The port number to which the proxy will forward data. 
                Defaults to `None`.
        """

        super().__init__()

        self.listen_ip: str | None = listen_ip
        """IP address where the proxy will listen for incoming connections."""

        self.listen_port: int | None = listen_port
        """Port number where the proxy will listen for incoming connections."""

        self.forward_from_ip: str | None = forward_from_ip
        """IP address from which the proxy will forward data."""

        self.forward_to_ip: str | None = forward_to_ip
        """IP address to which the proxy will forward data."""

        self.forward_to_port: int | None = forward_to_port
        """Port number to which the proxy will forward data."""

        # socket listening for incoming connections
        self._server_socket: SctpSocketT | None = None
        self._source = ProxyEndpoint('Source')

        # socket forwarding data to the target
        self._forward_socket: SctpSocketT | None = None
        self._target = ProxyEndpoint('Target')

    @property
    def source(self) -> Publisher:
        """Get the source endpoint of the SCTP proxy.

        The source endpoint is responsible for receiving data from and sending data to the client 
        connecting to the SCTP proxy.

        Returns:
            Publisher: An instance of `Publisher` representing the source endpoint.
        """

        return self._source

    @property
    def target(self) -> Publisher:
        """Get the target endpoint of the SCTP proxy.

        The target endpoint is responsible for receiving data from and sending data to the server 
        to which the SCTP proxy forwards data to.

        Returns:
            Publisher: An instance of `Publisher` representing the target endpoint.
        """

        return self._target

    def _is_socket_open(self, sock: SctpSocketT) -> bool:
        """Checks if a socket is open.

        Args:
            sock: The SCTP socket to check.

        Returns:
            bool: `True` if the socket is open, `False` otherwise.
        """

        return sock.fileno() != -1

    def _handle_sctp_connection(self, connection_socket: SctpSocketT, peer_info: tuple[str, int]):
        """Handle an SCTP connection.

        This function is responsible for managing an SCTP connection between a client connecting to 
        the SCTP proxy, and the SCTP server to which the proxy will connect to.

        Args:
            connection_socket: The SCTP socket representing the client connection to the SCTP proxy.
            peer_info: A tuple containing the IP address and port number of the client connected to 
                the SCTP proxy.
        """

        logging.info("Accepted connection from %s",
                     peer_info[0], extra={'entity': 'Proxy'})

        # setup SCTP target socket
        self._forward_socket = cast(
            SctpSocketT, sctp.sctpsocket_tcp(socket.AF_INET))
        self._forward_socket.bind((self.forward_from_ip, 0))
        self._forward_socket.events.peer_error = True
        self._forward_socket.events.shutdown = True
        self._forward_socket.connect(
            (self.forward_to_ip, self.forward_to_port))
        logging.info("Connected to forward server at %s:%s",
                     self.forward_to_ip, self.forward_to_port, extra={'entity': 'Proxy'})

        self._source.socket = connection_socket
        self._target.socket = self._forward_socket

        self._source.start()
        self._target.start()

        while not self.stop_event.is_set() \
                and self._is_socket_open(self._forward_socket) \
                and self._is_socket_open(connection_socket):
            time.sleep(0.1)

        # close the connections and reset the endpoints
        self._target.stop()
        self._source.stop()
        self._source.socket = self._target.socket = None
        self._forward_socket.close()
        connection_socket.close()
        logging.info("Closed connection to %s",
                     peer_info[0], extra={'entity': 'Proxy'})

    @override
    def handled_run(self):
        """Start the SCTP proxy.

        This function spin up an SCTP server listening for incoming connections on the interface 
        `listen_ip` and the port `listen_port`. Each new incoming connection will be handled by the 
        method `_handle_sctp_connection`.

        Raises:
            AgentError: In the following cases:
                1. If one between `listen_ip`, `listen_port`, `forward_from_ip`, `forward_to_ip` 
                    and `forward_to_port` is not set.
                2. If either the `bind`, `listen`, or `accept` socket function fails.
        """

        if self.listen_ip is None or self.listen_port is None:
            raise AgentError('Listen IP/port not specified')

        if self.forward_from_ip is None:
            raise AgentError('IP from which to forward not specified')

        if self.forward_to_ip is None or self.forward_to_port is None:
            raise AgentError('Destination IP/port not specified')

        # setup SCTP source server socket
        self._server_socket = cast(
            SctpSocketT, sctp.sctpsocket_tcp(socket.AF_INET))
        try:
            self._server_socket.bind((self.listen_ip, self.listen_port))
        except OSError as e:
            msg = f"Error on binding: {e}"
            logging.error(msg, extra={'entity': 'Proxy'})
            self.is_error_recoverable = False
            raise AgentError(msg) from e

        self._server_socket.settimeout(0.5)
        self._server_socket.events.peer_error = True
        self._server_socket.events.shutdown = True

        logging.info("Starting SCTP proxy on %s:%s",
                     self.listen_ip, self.listen_port, extra={'entity': 'Proxy'})
        logging.info("Forwarding to %s:%s from %s", self.forward_to_ip,
                     self.forward_to_port, self.forward_from_ip, extra={'entity': 'Proxy'})

        try:
            self._server_socket.listen(1)
        except OSError as e:
            msg = f"Error on listend: {e}"
            logging.error(msg, extra={'entity': 'Proxy'})
            self.is_error_recoverable = False
            raise AgentError(msg) from e

        while not self.stop_event.is_set():
            try:
                client_socket, peer_info = self._server_socket.accept()
            except TimeoutError:
                pass
            except OSError as e:
                self._server_socket.close()
                msg = f"Error on accept: {e}"
                logging.error(msg, extra={'entity': 'Proxy'})
                self.is_error_recoverable = True
                raise AgentError(msg) from e
            else:
                self._handle_sctp_connection(client_socket, peer_info)

        self._server_socket.close()
        logging.info("SCTP proxy stopped", extra={'entity': 'Proxy'})


class PublisherProxyAgent(Publisher):
    """A class representing a `Publisher` that interacts with an SCTP proxy.

    This class provides a bridge between the Publisher and the SCTP proxy, allowing the Publisher 
    to send and receive data through the proxy.
    """

    def __init__(self, pub_id: int, agent: "SctpProxyAgent"):
        """Initialize a new `PublisherProxyAgent` instance.

        Args:
            pub_id: The unique identifier of the Publisher.
            agent: The SCTP proxy agent that this Publisher interacts with.
        """

        self._pub_id = pub_id
        self._agent = agent

    @override
    def start(self):
        try:
            self._agent.start(self._pub_id)
        except AgentError as e:
            raise PublisherOperationError(str(e)) from e

    @override
    def stop(self):
        try:
            self._agent.stop(self._pub_id)
        except AgentError as e:
            raise PublisherOperationError(str(e)) from e

    @override
    def send(self, data: bytes):
        try:
            self._agent.send(self._pub_id, data)
        except AgentError as e:
            raise PublisherOperationError(str(e)) from e

    @override
    def receive(self) -> bytes:
        try:
            return self._agent.receive(self._pub_id)
        except AgentError as e:
            raise PublisherOperationError(str(e)) from e

    @override
    def data_available(self) -> bool:
        try:
            return self._agent.data_available(self._pub_id)
        except AgentError as e:
            raise PublisherOperationError(str(e)) from e

    def __hash__(self) -> int:
        return hash(self._pub_id)


@register(Agent)
class SctpProxyAgent(GrpcClientAgent):
    """Agent that controls an SCTP proxy."""

    @override
    @property
    def actors(self) -> list[str]:
        return [PUBLISHER_SOURCE_NAME, PUBLISHER_TARGET_NAME]

    @override
    def get(self, actor: str) -> Publisher | None:
        if actor == PUBLISHER_SOURCE_NAME:
            return self.get_source()

        if actor == PUBLISHER_TARGET_NAME:
            return self.get_target()

        return None

    def get_source(self) -> Publisher:
        """Get the source endpoint of the SCTP proxy.

        The source endpoint is responsible for receiving data from and sending data to the client 
        connecting to the SCTP proxy.

        Returns:
            Publisher: An instance of `Publisher` representing the source endpoint.
        """

        return PublisherProxyAgent(PUBLISHER_SOURCE_ID, self)

    def get_target(self) -> Publisher:
        """Get the target endpoint of the SCTP proxy.

        The target endpoint is responsible for receiving data from and sending data to the server 
        to which the SCTP proxy forwards data to.

        Returns:
            Publisher: An instance of `Publisher` representing the target endpoint.
        """

        return PublisherProxyAgent(PUBLISHER_TARGET_ID, self)

    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                - 'listen': A dictionary with the following key-value pairs:
                    - 'ip': A string representing the IP address where the SCTP proxy will listen
                        on.
                    - 'port': A number representing the SCTP port where the proxy will listen on.
                - 'forward': A dictionary with the following key-value pairs:
                    - 'from_ip': A string representing the IP address from which the SCTP proxy 
                        will forward data.
                    - 'to_ip': A string representing the IP address to which the SCTP proxy will 
                        forward data.
                    - 'to_port': A number representing the SCTP port to which the proxy will 
                        forward data.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method
                `stop_execution` is called.
        """

        super().set_options(**kwargs)

    @override
    def get_supported_paths(self, protocol: str) -> list[list[str]]:
        return []

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        return []

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return False

    @override
    def fault_detected(self) -> bool:
        return False

    @override
    def on_fault(self):
        return


class SctpProxyServerAgent(GrpcServerAgent):
    """Server agent that controls the UERANSIM tools."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._proxy: SctpProxy | None = None
        self._proxy_configs: dict[str, str | int] = {}
        self._publisher_map: dict[int, Publisher] = {}

    @override
    def set_options(self, **kwargs):
        if 'listen' in kwargs:
            listen_configs = kwargs['listen']
            if 'ip' in listen_configs:
                self._proxy_configs['listen_ip'] = listen_configs['ip']
                logging.info('Set listen[%s] = %s',
                             'ip', listen_configs['ip'])
            if 'port' in listen_configs:
                self._proxy_configs['listen_port'] = listen_configs['port']
                logging.info('Set listen[%s] = %s',
                             'port', listen_configs['port'])

        if 'forward' in kwargs:
            forward_configs = kwargs['forward']
            if 'from_ip' in forward_configs:
                self._proxy_configs['forward_from_ip'] = forward_configs['from_ip']
                logging.info('Set forward[%s] = %s',
                             'from_ip', forward_configs['from_ip'])
            if 'to_ip' in forward_configs:
                self._proxy_configs['forward_to_ip'] = forward_configs['to_ip']
                logging.info('Set forward[%s] = %s',
                             'to_ip', forward_configs['to_ip'])
            if 'to_port' in forward_configs:
                self._proxy_configs['forward_to_port'] = forward_configs['to_port']
                logging.info('Set forward[%s] = %s',
                             'to_port', forward_configs['to_port'])

    @override
    def on_test_start(self, ctx: ExecutionContext):
        self._proxy = SctpProxy(**self._proxy_configs)
        self._publisher_map[PUBLISHER_SOURCE_ID] = self._proxy.source
        self._publisher_map[PUBLISHER_TARGET_ID] = self._proxy.target
        self._proxy.start()
        time.sleep(0.1)

        if self._proxy.is_error_occurred:
            self._publisher_map = {}
            self._proxy.join()
            raise self._proxy.exception

    @override
    def on_test_end(self):
        self._publisher_map = {}
        self._proxy.join()

        if self._proxy.is_error_occurred:
            raise self._proxy.exception

    @override
    def redo_test(self) -> bool:
        return self._proxy.is_error_occurred and self._proxy.is_error_recoverable

    @override
    def stop_execution(self) -> bool:
        return self._proxy.is_error_occurred and not self._proxy.is_error_recoverable

    @override
    def start(self, pub_id: int):
        if pub_id not in self._publisher_map:
            raise AgentError(f"Publisher with ID {pub_id} not found")

        try:
            self._publisher_map[pub_id].start()
        except PublisherOperationError as e:
            raise AgentError(str(e)) from e

    @override
    def stop(self, pub_id: int):
        if pub_id not in self._publisher_map:
            raise AgentError(f"Publisher with ID {pub_id} not found")

        try:
            self._publisher_map[pub_id].stop()
        except PublisherOperationError as e:
            raise AgentError(str(e)) from e

    @override
    def send(self, pub_id: int, data: bytes):
        if pub_id not in self._publisher_map:
            raise AgentError(f"Publisher with ID {pub_id} not found")

        try:
            self._publisher_map[pub_id].send(data)
        except PublisherOperationError as e:
            raise AgentError(str(e)) from e

    @override
    def receive(self, pub_id: int) -> bytes:
        if pub_id not in self._publisher_map:
            raise AgentError(f"Publisher with ID {pub_id} not found")

        try:
            return self._publisher_map[pub_id].receive()
        except PublisherOperationError as e:
            raise AgentError(str(e)) from e

    @override
    def data_available(self, pub_id: int) -> bool:
        if pub_id not in self._publisher_map:
            raise AgentError(f"Publisher with ID {pub_id} not found")

        try:
            return self._publisher_map[pub_id].data_available()
        except PublisherOperationError as e:
            raise AgentError(str(e)) from e


__all__ = ['SctpProxyAgent']


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Agent that sniff packets on the machine.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG,
                        format="[%(entity)s][%(levelname)s] - %(message)s")

    class DefaultEntityFilter(logging.Filter):
        @override
        def filter(self, record):
            if not hasattr(record, 'entity'):
                record.entity = "Server"
            return True

    logging.getLogger("root").addFilter(DefaultEntityFilter())

    agent = SctpProxyServerAgent(address=args.ip, port=args.port)

    agent.serve()
