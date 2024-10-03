import logging
import socket
import threading
import select
import time
from queue import SimpleQueue

import sctp

from ..publisher import NetworkPublisher, PublisherError


RECV_BUFF_LEN = 4096
SELECT_TIMEOUT = 0.1


class ProxyEndpoint(NetworkPublisher):
    """A class representing one endpoint of the SCTP proxy.

    This class handles the arrival and delivery of data from one endpoint of the SCTP proxy. It 
    also acts as a `NetworkPublisher` for the fuzzer.

    Attributes:
        socket: The source SCTP socket for this endpoint.
        dst: The destination SCTP socket for this endpoint.
        input_queue: A queue for storing incoming data.
        output_queue: A queue for storing outgoing data.
    """

    def __init__(self, ip: str, port: int, proxy):
        """Initialize a `ProxyEndpoint` instance.

        Parameters:
            ip: The IP address of the proxy endpoint.
            port: The port number of the proxy endpoint.
            proxy (SctpProxy): The SCTP proxy instance that manages this endpoint.
        """

        super().__init__(ip, port)

        self.socket: sctp.sctpsocket | None = None
        self.dst: sctp.sctpsocket | None = None
        self._proxy = proxy

        # since SimpleQueue methods are thread-safe, we can safely use them as communication method
        # between the main thread and the proxy thread without the need to use locks by ourselves
        self.input_queue: SimpleQueue = SimpleQueue()
        self.output_queue: SimpleQueue = SimpleQueue()

    def start(self):
        self._proxy.start()

    def stop(self):
        self._proxy.stop()

    @property
    def started(self) -> bool:
        return self._proxy.is_running

    def send(self, data: bytes):
        if not self._proxy.is_running:
            raise PublisherError("the proxy is not running")

        self.output_queue.put(data)

    def receive(self) -> bytes | None:
        if not self._proxy.is_running:
            raise PublisherError("the proxy is not running")

        if self.input_queue.empty():
            return None

        return self.input_queue.get()

    def data_available(self) -> bool:
        if not self._proxy.is_running:
            raise PublisherError("the proxy is not running")

        return not self.input_queue.empty()

    def fileno(self) -> int:
        """Return the file descriptor of the source socket.

        Returns:
            int: The file descriptor of the socket.
        """

        # pylint: disable=protected-access
        return self.socket._sk.fileno()


class SctpProxy:
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

    def __init__(self, listen_ip: str, listen_port: int, forward_from_ip: str, forward_to_ip: str, forward_to_port: int):
        """Initializes an SCTP proxy instance.

        Args:
            listen_ip: The IP address where the proxy will listen for incoming connections.
            listen_port: The port number where the proxy will listen for incoming connections.
            forward_from_ip: The IP address from which the proxy will forward data.
            forward_to_ip: The IP address to which the proxy will forward data.
            forward_to_port: The port number to which the proxy will forward data.
        """

        self.listen_ip: str = listen_ip
        self.listen_port: int = listen_port
        self.forward_from_ip: str = forward_from_ip
        self.forward_to_ip: str = forward_to_ip
        self.forward_to_port: int = forward_to_port

        # socket listening for incoming connections
        self._server_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        self._server_socket.bind((listen_ip, listen_port))
        self._server_socket.events.peer_error = True
        self._server_socket.events.shutdown = True

        # source of messages for the fuzzer
        self._source = ProxyEndpoint(self.listen_ip, self.listen_port, self)

        # socket forwarding data to the target
        self._forward_socket = sctp.sctpsocket_tcp(socket.AF_INET)
        self._forward_socket.bind((forward_from_ip, 0))
        self._forward_socket.events.peer_error = True
        self._forward_socket.events.shutdown = True

        # target for the fuzzer
        self._target = ProxyEndpoint(
            self.forward_to_ip, self.forward_to_port, self)

        self._logger: logging.Logger = logging.getLogger('SCTP Proxy')

        # flag indicating whether the proxy should stop
        self._stop_flag: threading.Event = threading.Event()
        self._stop_flag.set()

        # thread running the proxy
        self._thread: threading.Thread = threading.Thread(
            target=self._start_callback)

    @property
    def is_running(self) -> bool:
        """Returns whether the SCTP proxy is currently running.

        Returns:
            bool: True if the proxy is running, False otherwise.
        """

        return not self._stop_flag.is_set()

    def get_source(self) -> NetworkPublisher:
        """Returns the source endpoint of the SCTP proxy.

        The source endpoint is responsible for receiving data from the local listening IP and port.

        Returns:
            NetworkPublisher: An instance of `NetworkPublisher` representing the source endpoint.
        """

        return self._source

    def get_target(self) -> NetworkPublisher:
        """Returns the target endpoint of the SCTP proxy.

        The target endpoint is responsible for sending data to the remote IP and port.

        Returns:
            NetworkPublisher: An instance of `NetworkPublisher` representing the target endpoint.
        """

        return self._target

    def start(self):
        """Start the SCTP proxy.

        The method checks if the proxy is already running. If not, it starts a new thread to run 
        the proxy.
        """

        # skip if already started
        if not self._stop_flag.is_set():
            return

        self._logger.info("Starting SCTP proxy on %s:%s",
                          self.listen_ip, self.listen_port)
        self._logger.info("Forwarding to %s:%s from %s", self.forward_to_ip,
                          self.forward_to_port, self.forward_from_ip)

        self._stop_flag.clear()
        self._thread.start()

    def stop(self):
        """Stop the SCTP proxy.

        This method checks if the proxy is already stopped. If not, it stops the thread running the 
        proxy code.
        """

        # skip if already stopped
        if self._stop_flag.is_set():
            return

        self._stop_flag.set()
        self._logger.info("Stopping SCTP proxy")

    def _handle_sctp_connection(self, connection_socket: sctp.sctpsocket_tcp):
        """Handle an SCTP connection.

        This function is responsible for managing an SCTP connection between a client connecting to 
        the SCTP server, and an SCTP client connecting to a remote server.

        Args:
            connection_socket: The SCTP socket representing the client connection to the local SCTP 
                server.
        """

        self._logger.info("Accepted connection from %s",
                          connection_socket.socket.getpeername())

        self._forward_socket.connect(
            (self.forward_to_ip, self.forward_to_port))
        self._logger.info("Connected to forward server at %s:%s",
                          self.forward_to_ip, self.forward_to_port)

        self._source.socket = connection_socket
        self._source.dst = self._forward_socket

        self._target.socket = self._forward_socket
        self._target.dst = connection_socket

        # loop until either the connection is closed or the proxy is stopped
        endpoints = [self._source, self._target]
        while not self._stop_flag.is_set():
            # wait for data to be available on either endpoint or for a timeout
            ready, _, _ = select.select(endpoints, [], [], SELECT_TIMEOUT)
            for endpoint in ready:
                try:
                    _, _, data, _ = endpoint.socket.sctp_recv(RECV_BUFF_LEN)
                except (TimeoutError, ConnectionError) as e:
                    logging.error("Error while receiving data: %s", e)
                    break

                # if no data is available it means the connection has been closed
                if data is None:
                    endpoint.dst.close()
                    self._logger.info("Closed connection to %s",
                                      connection_socket.getpeername())
                    return

                # put received data into the endpoint's input queue
                endpoint.input_queue.put(data)

            # send all the data in the output queues of the endpoints to the destination socket
            for endpoint in endpoints:
                while not endpoint.output_queue.empty():
                    data = endpoint.output_queue.get()
                    try:
                        endpoint.dst.sctp_send(data, ppid=socket.ntohl(60))
                    except OSError as e:
                        logging.error("Error while sending data: %s", e)

            time.sleep(SELECT_TIMEOUT)

        # close the connections and reset the endpoints
        self._target.socket.close()
        self._source.socket.close()
        self._source.socket = self._target.socket = None
        self._source.dst = self._target.dst = None
        self._logger.info("Closed connection to %s",
                          connection_socket.getpeername())

    def _start_callback(self):
        """Callback method for the proxy thread.

        This function is the callback method that runs in a separate thread to handle a single 
        incoming SCTP connection. It listens for the incoming connection on the server socket, 
        accepts it, and handles it using the `_handle_sctp_connection` method.

        Note: The decision to run also the SCTP listener on a thread different from the main one is 
        determined by the fact that in this way we can continue to execute other code in the fuzzer 
        while waiting for a new connection.
        """

        self._server_socket.listen(1)

        # loop until the proxy is stopped
        while not self._stop_flag.is_set():
            try:
                client_socket, _ = self._server_socket.accept()
                self._handle_sctp_connection(client_socket)
            except OSError as e:
                self._logger.error("Error accepting connections: %s", e)
