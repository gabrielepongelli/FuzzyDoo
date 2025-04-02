# pylint: disable=too-many-lines

import argparse
import sys
import logging
import socket
import time
import re
from queue import Empty, Queue, ShutDown
from typing import cast, override, Generic, TypeVar, Any
from select import select
from abc import ABC, abstractmethod
from collections.abc import Callable
from threading import Lock

import sctp
from pycrate_asn1dir import NGAP as ngap
from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_core.utils import PycrateErr

from ..protocol import Message
from ..proto.nas.messages import NASMessage
from ..transformers.nas_security import NASSecurity
from ..publisher import Publisher
from ..agent import Agent, ExecutionContext
from ..utils.threads import EventStoppableThread, ExceptionRaiserThread
from ..utils.register import register
from ..utils.network import PYCRATE_NGAP_STRUCT_LOCK
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


RECV_BUFF_LEN = 4096
SELECT_TIMEOUT = 0.1

PUBLISHER_SOURCE_ID = 1
PUBLISHER_SOURCE_NAME = 'source'
PUBLISHER_TARGET_ID = 2
PUBLISHER_TARGET_NAME = 'target'


_NGAP_RELEVANT_IE_PATHS: dict[str, Callable[[dict], list[str | int] | None]] = {
    'NAS-PDU': lambda ie: ['value', ie['value'][0]],
    'PDUSessionResourceSetupListSUReq':
    lambda ie: (['value', ie['value'][0], 0, 'pDUSessionNAS-PDU']
                if 'pDUSessionNAS-PDU' in ie['value'][1][0].keys()
                else None),
    'PDUSessionResourceModifyListModReq':
    lambda ie: (['value', ie['value'][0], 0, 'nAS-PDU']
                if 'nAS-PDU' in ie['value'][1][0].keys()
                else None),
    'NASC': lambda ie: ['value', ie['value'][0]],
}


def extract_from_ngap(data: bytes) -> tuple[bytes, list | None]:
    """Extract inner data from the given NGAP data.

    This function attempts to parse the input NGAP data and extract data related to some inner 
    protocol, if any.

    Note: This function internally uses `PYCRATE_NGAP_STRUCT_LOCK`.

    Args:
        data: The raw NGAP data to be parsed and extracted.

    Returns:
        tuple[bytes, list | None]: A tuple containing:
            - bytes: The extracted inner data if successful, or the original input data if the 
                extraction fails.
            - list | None: The path used for successful extraction, or `None` if extraction fails.
    """

    with PYCRATE_NGAP_STRUCT_LOCK:
        ngap_pdu = ngap.NGAP_PDU_Descriptions.NGAP_PDU
        try:
            from_aper = cast(Callable[[Any], None], ngap_pdu.from_aper)
            from_aper(data)
        except PycrateErr:
            return data, None

        ngap_content = ngap_pdu.get_val()
        for idx, ie in enumerate(ngap_content[1]['value'][1]['protocolIEs']):
            get_data_path = _NGAP_RELEVANT_IE_PATHS.get(ie['value'][0], lambda _: None)
            data_path = get_data_path(ie)
            if data_path is not None:
                data_path = [
                    ngap_content[0],
                    'value',
                    ngap_content[1]['value'][0],
                    'protocolIEs',
                    idx
                ] + data_path

                try:
                    return ngap_pdu.get_val_at(data_path), data_path
                except PycrateErr:
                    pass
        return data, None


def include_in_ngap(msg: bytes, data: bytes, path: list) -> bytes | None:
    """Include the given data into an NGAP message at the specified path.

    This function attempts to insert the provided data into an NGAP message at the location 
    specified by the path.

    Note: This function internally uses `PYCRATE_NGAP_STRUCT_LOCK`.

    Args:
        msg: The original bytes that compose the NGAP message.
        data: The data to be included in the NGAP message.
        path: A list representing the path in the NGAP message structure where the data should be 
            inserted (see `extract_from_ngap`).

    Returns:
        bytes | None: The encoded NGAP message with the included data if successful, or `None` if 
            an error occurs during the process.
    """

    with PYCRATE_NGAP_STRUCT_LOCK:
        ngap_pdu = ngap.NGAP_PDU_Descriptions.NGAP_PDU
        try:
            from_aper = cast(Callable[[Any], None], ngap_pdu.from_aper)
            from_aper(msg)
        except PycrateErr:
            return None

        try:
            ngap_pdu.set_val_at(path, data)
            return ngap_pdu.to_aper()
        except PycrateErr as e:
            logging.warning(e)
            logging.warning(ngap_pdu.get_val())
            return None


def extract_from_nas_mm(data: bytes, decipher: NASSecurity, src: str, dst: str) -> tuple[bytes, Message]:
    """Extract inner data from the given NAS-MM data.

    This function attempts to parse the input NAS-MM data and extract data related to some inner 
    protocol, if any.

    Args:
        data: The raw NAS-MM data to be parsed and extracted.
        decipher: The NAS security object to use for decryption.
        src: The name in the NAS-MM protocol of the entity that sent the data.
        dst: The name in the NAS-MM protocol of the entity that the data is intended for.

    Returns:
        tuple[bytes, Message]: A tuple containing:
            - bytes: The extracted inner data if successful, or the original input data if the 
                extraction fails.
            - Message: The parsed NAS-MM message if parsing is successful, or `None` if parsing fails.
    """

    nas_pdu, err = parse_NAS5G(data, inner=False)
    if err:
        return data, None

    # pylint: disable=protected-access
    if nas_pdu.__class__.__name__ == 'FGMMSecProtNASMessage':
        msg = NASMessage('MM', 'FGMMSecProtNASMessage', nas_pdu)
    else:
        try:
            msg = Message.from_name('NAS-MM', nas_pdu.__class__.__name__ + 'Message')
            msg = msg.parse(data)
        except (MessageParsingError, UnknownMessageError):
            return data, None

    try:
        msg = decipher.decode(msg, src, dst)
    except DecodingError:
        return data, None

    if msg.name not in {'FGMMULNASTransportMessage', 'FGMMDLNASTransportMessage'}:
        return data, None

    return msg.content['PayloadContainer']['V'], msg


def include_in_nas_mm(msg: NASMessage, data: bytes, cipher: NASSecurity, src: str, dst: str) -> bytes | None:
    """Include the given data into a NAS-MM message at the specified path.

    This function attempts to insert the provided data into an NAS-MM message.

    Args:
        msg: The NAS-MM message object to modify.
        data: The data to be included in the NAS-MM message.
        cipher: The NAS security object to use for encryption.
        src: The name in the NAS-MM protocol of the entity that sent the data.
        dst: The name in the NAS-MM protocol of the entity that the data is intended for.

    Returns:
        bytes | None: The encoded NAS-MM message with the included data if successful, or `None` if 
            an error occurs during the process.
    """

    try:
        # check if ['PayloadContainer']['V'] exist in msg
        qname = msg.qualified_name + '.PayloadContainer.V'
        msg.get_content(qname)

        msg.set_content(qname, data)
        encrypted_msg = cipher.encode(msg, src, dst)
        return encrypted_msg.raw()
    except (EncodingError, ContentNotFoundError, PycrateErr):
        return None


class ProxyError(FuzzyDooError):
    """Generic error occurred during proxy operations."""


class MissingConfigError(ProxyError):
    """Error raised if at least one required configuration parameter is missing."""


class SocketError(ProxyError):
    """Error raised if either the `bind`, `listen`, `accept` or `connect` socket function fails."""


SocketT = TypeVar('SocketT', bound=socket.socket)


# since sctp.sctpsocket is not well type-hinted, in this way we can have correct type hints also
# for the standard socket.socket methods
SctpSocketT = sctp.sctpsocket | socket.socket


class EndpointReceiverThread(EventStoppableThread, ExceptionRaiserThread, Generic[SocketT], ABC):
    """A thread class responsible for receiving data from a socket.

    This class extends `EventStoppableThread` and `ExceptionRaiserThread` to provide controlled
    execution and error handling capabilities. It continuously reads data from the assigned
    socket and places it into a queue for further processing.
    """

    socket: SocketT | None
    """The socket from which data will be read."""

    queue: Queue
    """A thread-safe queue where received data packets are stored."""

    sender_queue: Queue | None
    """A thread-safe queue whose inner elements are sent by the sender thread."""

    def __init__(self, sock: SocketT | None = None, sender_queue: Queue | None = None):
        """Initialize a new `EndpointReceiverThread` instance.

        Args:
            sock: The socket from which data will be read.
            sender_queue: A thread-safe queue whose inner elements are sent by the sender thread.
        """

        super().__init__()

        self.socket = sock
        self.queue = Queue()
        self.sender_queue = sender_queue

    @abstractmethod
    def _recv(self, size: int) -> bytes:
        """Receive data from the socket.

        Args:
            size: The maximum number of bytes to read.

        Returns:
            bytes: The received data.
        """

    def _directly_forward_data(self, data: bytes) -> bool:
        """Check if the data provided should be forwarded directly to the sender queue.

        Args:
            data: The received data.

        Returns:
            bool: `True` if the data should be forwarded, `False` otherwise.
        """

        return False

    def handled_run(self):
        """The main execution method of the thread.

        This method continuously receives data from the socket and puts it in the queue.
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
                    data = self._recv(RECV_BUFF_LEN)
                except (TimeoutError, ConnectionError) as e:
                    self.queue.shutdown(True)
                    self.is_error_recoverable = True
                    raise PublisherOperationError(f"Error while receiving data: {e}") from e
                except OSError:
                    pass
                else:
                    if not data:
                        break  # EOF reached

                    try:
                        if self._directly_forward_data(data):
                            self.sender_queue.put_nowait(data)
                        else:
                            self.queue.put_nowait(data)
                    except ShutDown:
                        break

        self.queue.shutdown(True)


class SCTPEndpointReceiverThread(EndpointReceiverThread[SctpSocketT]):
    """An `EndpointReceiverThread` that receives data from an SCTP socket."""

    @override
    def _recv(self, size: int) -> bytes:
        _, _, data, _ = self.socket.sctp_recv(size)
        return data


class NGAPEndpointReceiverThread(SCTPEndpointReceiverThread):
    """A specialized `EndpointReceiverThread` that handle NGAP packets over an SCTP socket."""

    @override
    def _directly_forward_data(self, data: bytes) -> bool:
        res = extract_from_ngap(data)[0] == data
        return res


class NASMMEndpointReceiverThread(NGAPEndpointReceiverThread):
    """A specialized `EndpointReceiverThread` for handling NAS-MM packets over an NGAP connection.

    This class extends `NGAPEndpointReceiverThread` to provide additional functionality for 
    processing NAS-MM packets. It utilizes a NAS security transformer to decrypt and process the 
    received NAS-MM data, ensuring secure communication between endpoints.
    """

    transformer: NASSecurity | None
    """The NAS security transformer to be applied to the received data."""

    transformer_lock: Lock | None
    """The lock for multithreading access to `transformer`."""

    def __init__(self, sock: SocketT | None = None, sender_queue: Queue | None = None, entity: str | None = None, transformer: tuple[NASSecurity, Lock] | None = None):
        """Initialize a new `NASMMEndpointReceiverThread` instance.

        Args:
            sock: The socket from which data will be read.
            sender_queue: A thread-safe queue whose inner elements are sent by the sender thread.
            entity: The name of this endpoint.
            transformer: The NAS security transformer to be applied to the received data and its 
                related lock for multithreading access.
        """

        super().__init__(sock, sender_queue)

        self.transformer = transformer[0] if transformer else None
        self.transformer_lock: Lock | None = transformer[1] if transformer else None
        self._name: str | None = None
        self._dst_name: str | None = None
        if entity is not None:
            self.entity = entity

    @property
    def entity(self) -> str:
        """The name of this endpoint."""

        return PUBLISHER_TARGET_NAME if self._name == 'AMF' else PUBLISHER_SOURCE_NAME

    @entity.setter
    def entity(self, name: str) -> str:
        self._name = 'AMF' if name == PUBLISHER_TARGET_NAME else 'UE'
        self._dst_name = 'AMF' if self._name == 'UE' else 'UE'
        return name

    @override
    def _directly_forward_data(self, data: bytes) -> bool:
        ngap_data, _ = extract_from_ngap(data)
        if ngap_data == data:
            return True

        with self.transformer_lock:
            nas_data, _ = extract_from_nas_mm(
                ngap_data, self.transformer, self._name, self._dst_name)

        return nas_data == ngap_data


class EndpointSenderThread(EventStoppableThread, ExceptionRaiserThread, Generic[SocketT], ABC):
    """A thread class responsible for sending data through a socket.

    This class extends `EventStoppableThread` and `ExceptionRaiserThread` to provide controlled
    execution and error handling capabilities. It continuously takes data from a queue and sends it
    through the assigned socket.
    """

    socket: SocketT | None
    """The socket through which data will be sent."""

    queue: Queue
    """A thread-safe queue from which data packets to be sent are taken."""

    def __init__(self, sock: SocketT | None = None):
        """Initialize a new `EndpointSenderThread` instance.

        Args:
            sock: The socket through which data will be sent.
        """

        super().__init__()

        self.socket = sock
        self.queue = Queue()

    @abstractmethod
    def _send(self, data: bytes):
        """Send the specified data through the socket.

        Args:
            data: The data to be sent.
        """

    def handled_run(self):
        """The main execution method of the thread.

        This method continuously takes data from the queue and sends it through the socket.
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
                self._send(data)
            except OSError as e:
                self.queue.shutdown(True)
                self.is_error_recoverable = True
                raise PublisherOperationError(f"Error while sending data: {e}") from e
            self.queue.task_done()

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


class SCTPEndpointSenderThread(EndpointSenderThread[SctpSocketT]):
    """An `EndpointSenderThread` that sends data through an SCTP socket."""

    @override
    def _send(self, data):
        self.socket.sctp_send(data, ppid=socket.ntohl(60))


class NGAPEndpointSenderThread(SCTPEndpointSenderThread):
    """A specialized `EndpointSenderThread` that handle NGAP packets over an SCTP socket."""


class NASMMEndpointSenderThread(NGAPEndpointSenderThread):
    """A specialized `EndpointSenderThread` for handling NAS-MM packets over an NGAP connection."""


class ProxyEndpoint(Publisher, Generic[SocketT], ABC):
    """A class representing one endpoint of the network proxy.

    This class handles the arrival and delivery of data from one endpoint of the network proxy.
    """

    name: str
    """Name of this entpoint."""

    socket: SocketT | None
    """Socket for this endpoint."""

    is_error_recoverable: bool
    """Whether the error, if any, is recoverable or not."""

    def __init__(self, name: str, sock: SocketT | None = None):
        """Initialize a new `ProxyEndpoint` instance.

        Parameters:
            name: The name of this entpoint.
            socket (optional): The socket for this endpoint. Defaults to `None`.
        """

        self.name = name
        self.socket = sock
        self.is_error_recoverable = True
        self._sender, self._receiver = self._get_communication_threads()

    @abstractmethod
    def _get_communication_threads(self) -> tuple[EndpointSenderThread[SocketT], EndpointReceiverThread[SocketT]]:
        """Get the sender and receiver threads.

        This method is called in the constructor of the class after the other fields have been 
        initialized.

        Returns:
            tuple[EndpointSenderThread[SocketT], EndpointReceiverThread[SocketT]]: A tuple 
                containing the sender and receiver threads.
        """

    @abstractmethod
    def _setup_communication_threads(self):
        """Set up the sender and receiver threads."""

    @property
    def send_queue(self) -> Queue | None:
        """The sender queue."""

        if self._sender is None:
            return None
        return self._sender.queue

    @property
    def recv_queue(self) -> Queue | None:
        """The receiver queue."""

        if self._receiver is None:
            return None
        return self._receiver.queue

    @override
    def start(self):
        """Start the threads responsible for sending / receiving data form the socket.

        You need to set the `socket` attribute before calling this method, otherwise an
        exception will be raised.

        Raises:
            PublisherOperationError: If an error occurs while starting the threads.
        """

        if self.socket is None:
            msg = 'No socket provided'
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = False
            raise PublisherOperationError(msg)

        if self.is_running:
            return

        self._setup_communication_threads()
        self._sender.start()
        self._receiver.start()

        logging.info('Endpoint started', extra={'entity': self.name.capitalize()})

    @override
    def stop(self):
        """Stop the threads responsible for sending / receiving data form the socket.

        This will not close the socket, so that the connection can be recovered later.

        Raises:
            PublisherOperationError: If an error occurs while stopping the threads.
        """

        if self._sender is not None and self._sender.is_alive():
            self._sender.join()
        if self._receiver is not None and self._receiver.is_alive():
            self._receiver.join()

        logging.info('Endpoint stopped', extra={'entity': self.name.capitalize()})

        if self._sender and self._sender.is_error_occurred:
            msg = str(self._sender.exception)
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = self._sender.is_error_recoverable
            raise PublisherOperationError(msg)

        if self._receiver and self._receiver.is_error_occurred:
            msg = str(self._receiver.exception)
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = self._receiver.is_error_recoverable
            raise PublisherOperationError(msg)

    @property
    def is_running(self) -> bool:
        """Whether the current endpoint is running or not."""

        return self._sender is not None \
            and self._receiver is not None \
            and self._sender.is_alive() \
            and self._receiver.is_alive()

    def _process_before_send(self, data: bytes) -> bytes:
        """Process the data before it is sent with the `send` method.

        Args:
            data: The data to send.

        Returns:
            bytes: The processed data to send.
        """

        return data

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
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = True
            raise PublisherOperationError(msg)

        self.send_queue.put(self._process_before_send(data))
        if self._sender.is_error_occurred:
            msg = str(self._sender.exception)
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = self._sender.is_error_recoverable
            raise PublisherOperationError(msg)

    def _process_after_receive(self, data: bytes) -> bytes:
        """Process the received data before it is returned to the caller of the `receive` method.

        Args:
            data: The received data.

        Returns:
            bytes: The processed data.
        """

        return data

    @override
    def receive(self) -> bytes:
        """Receive some data from the endpoint.

        Returns:
            bytes: The received data. If no data is available(see `data_available`) then `b""` is
                returned.

        Raises:
            PublisherOperationError: If the endpoint is not running or if an error occurs while
                receiving the data.
        """

        if not self.is_running:
            msg = "The endpoint is not running"
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = True
            raise PublisherOperationError(msg)

        if self._receiver.is_error_occurred:
            msg = str(self._receiver.exception)
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = self._receiver.is_error_recoverable
            raise PublisherOperationError(msg)

        try:
            data = self.recv_queue.get_nowait()
            self.recv_queue.task_done()
            return self._process_after_receive(data)
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
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = True
            raise PublisherOperationError(msg)

        return not self.recv_queue.empty()

    def __hash__(self) -> int:
        return hash(tuple(self.name, self.socket.fileno()))


class SCTPProxyEndpoint(ProxyEndpoint[SctpSocketT]):
    """A `ProxyEndpoint` implementation for handling SCTP connections.

    This class provides the necessary sender and receiver threads to manage data transmission over 
    an SCTP socket, facilitating the forwarding of data between network endpoints using the SCTP 
    protocol.
    """

    endpoint_send_queue: Queue
    """The queue used by the other endpoint to send data."""

    def __init__(self, name: str, sock: SocketT | None = None, endpoint_send_queue: Queue | None = None):
        """Initialize a new `SCTPProxyEndpoint` instance.

        Parameters:
            name: The name of this entpoint.
            socket (optional): The socket for this endpoint. Defaults to `None`.
            endpoint_send_queue (optional): The queue used by the other endpoint to send data. 
                Defaults to a new queue instance.
        """

        super().__init__(name, sock)

        self.endpoint_send_queue = endpoint_send_queue if endpoint_send_queue is not None else Queue()

    @override
    def _get_communication_threads(self) -> tuple[SCTPEndpointSenderThread, SCTPEndpointReceiverThread]:
        sender = SCTPEndpointSenderThread()
        receiver = SCTPEndpointReceiverThread()
        return sender, receiver

    @override
    def _setup_communication_threads(self):
        self._sender.socket = self.socket
        self._receiver.socket = self.socket
        self._receiver.sender_queue = self.endpoint_send_queue

    @override
    def start(self):
        if self.socket is None:
            msg = 'No socket provided'
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = False
            raise PublisherOperationError(msg)

        if self.endpoint_send_queue is None:
            msg = 'No endpoint send queue provided'
            logging.error(msg, extra={'entity': self.name.capitalize()})
            self.is_error_recoverable = False
            raise PublisherOperationError(msg)

        if self.is_running:
            return

        self._setup_communication_threads()
        self._sender.start()
        self._receiver.start()

        logging.info('Endpoint started', extra={'entity': self.name.capitalize()})


class NGAPProxyEndpoint(SCTPProxyEndpoint):
    """A `ProxyEndpoint` implementation for handling NGAP packets.

    This class extends the SCTP proxy functionality to process NGAP messages, providing specialized 
    handling for sending and receiving NGAP data over an SCTP connection.
    """

    ngap_queue: Queue
    """The queue used to store original NGAP messages to be sent."""

    def __init__(self, name: str, sock: SocketT | None = None, endpoint_send_queue: Queue | None = None, ngap_queue: Queue | None = None):
        """Initialize a new `NGAPProxyEndpoint` instance.

        Parameters:
            name: The name of this entpoint.
            socket (optional): The socket for this endpoint. Defaults to `None`.
            endpoint_send_queue (optional): The queue used by the other endpoint to send data. 
                Defaults to a new queue instance.
            ngap_queue: (optional): The queue used to store original NGAP messages to be sent. 
                Defaults to a new queue instance.
        """

        super().__init__(name, sock, endpoint_send_queue)

        self.ngap_queue = ngap_queue if ngap_queue is not None else Queue()

    @override
    def _get_communication_threads(self) -> tuple[NGAPEndpointSenderThread, NGAPEndpointReceiverThread]:
        sender = NGAPEndpointSenderThread()
        receiver = NGAPEndpointReceiverThread()
        return sender, receiver

    @override
    def _process_before_send(self, data: bytes) -> bytes:
        msg, path = self.ngap_queue.get()
        self.ngap_queue.task_done()

        if msg is None and path is None:
            return data

        processed_data = include_in_ngap(msg, data, path)
        return processed_data if processed_data is not None else data

    @override
    def _process_after_receive(self, data: bytes) -> bytes:
        ngap_data, path = extract_from_ngap(data)
        self.ngap_queue.put((data, path))
        return ngap_data


class NASMMProxyEndpoint(NGAPProxyEndpoint):
    """A `ProxyEndpoint` implementation for handling NAS-MM packets.

    This class extends the NGAP proxy functionality to process NAS-MM messages, providing 
    specialized handling for sending and receiving NAS-MM data over an NGAP connection.
    """

    nas_queue: Queue
    """The queue used to store original NAS messages to be sent."""

    def __init__(self, name: str, transformer: tuple[NASSecurity, Lock], sock: SocketT | None = None, endpoint_send_queue: Queue | None = None, ngap_queue: Queue | None = None, nas_queue: Queue | None = None):
        """Initialize a new `NASMMProxyEndpoint` instance.

        Parameters:
            name: The name of this entpoint.
            socket (optional): The socket for this endpoint. Defaults to `None`.
            endpoint_send_queue (optional): The queue used by the other endpoint to send data. 
                Defaults to a new queue instance.
            ngap_queue: (optional): The queue used to store original NGAP messages to be sent. 
                Defaults to a new queue instance.
            nas_queue: (optional): The queue used to store original NAS messages to be sent. 
                Defaults to a new queue instance.
            transformer: The NAS security transformer to be applied to the received data and its 
                related lock for multithreading access.
        """

        super().__init__(name, sock, endpoint_send_queue, ngap_queue)

        self._tr: NASSecurity = transformer[0]
        """Transformer to use for encryption/decryption of NAS-MM packets."""

        self._tr_lock: Lock = transformer[1]
        """Lock for the access to `_tr`."""

        self.nas_queue = nas_queue if nas_queue is not None else Queue()

        self._src_name: str = 'AMF' if name == PUBLISHER_TARGET_NAME else 'UE'
        """The value of `src` for the `extract_from_nas_mm` function."""

        self._dst_name: str = 'AMF' if self._src_name == 'UE' else 'UE'
        """The value of `dst` for the `extract_from_nas_mm` function."""

    @override
    def _get_communication_threads(self) -> tuple[NASMMEndpointSenderThread, NASMMEndpointReceiverThread]:
        sender = NASMMEndpointSenderThread()
        receiver = NASMMEndpointReceiverThread()
        return sender, receiver

    @override
    def _setup_communication_threads(self):
        super()._setup_communication_threads()

        cast(NASMMEndpointReceiverThread, self._receiver).entity = self.name
        cast(NASMMEndpointReceiverThread, self._receiver).transformer = self._tr
        cast(NASMMEndpointReceiverThread, self._receiver).transformer_lock = self._tr_lock

    @override
    def _process_before_send(self, data: bytes) -> bytes:
        msg = self.nas_queue.get()
        self.nas_queue.task_done()

        if msg is None:
            return super()._process_before_send(data)

        with self._tr_lock:
            processed_data = include_in_nas_mm(msg, data, self._tr, self._dst_name, self._src_name)
            res = processed_data if processed_data is not None else data
            return super()._process_before_send(res)

    @override
    def _process_after_receive(self, data: bytes) -> bytes:
        data = super()._process_after_receive(data)
        with self._tr_lock:
            nas_data, msg = extract_from_nas_mm(data, self._tr, self._src_name, self._dst_name)
            self.nas_queue.put(msg)
            return nas_data


class NetworkProxy(EventStoppableThread, ExceptionRaiserThread, Generic[SocketT], ABC):
    """Abstract class representing a generic network proxy to forward data between two network endpoints.

    It allows for the forwarding of data between two network endpoints, enabling the capture and
    manipulation of packets. It can be started and stopped programmatically using the `start()` and
    `stop()` methods, respectively.
    """

    listen_ip: str | None
    """IP address where the proxy will listen for incoming connections."""

    listen_port: int | None
    """Port number where the proxy will listen for incoming connections."""

    forward_from_ip: str | None
    """IP address from which the proxy will forward data."""

    forward_to_ip: str | None
    """IP address to which the proxy will forward data."""

    forward_to_port: int | None
    """Port number to which the proxy will forward data."""

    fault_detected: bool
    """Flag indicating whether a fault has been detected."""

    def __init__(self,
                 listen_ip: str,
                 listen_port: int,
                 forward_from_ip: str,
                 forward_to_ip: str,
                 forward_to_port: int):
        """Initializes a new `NetworkProxy` instance.

        Args:
            listen_ip: The IP address where the proxy will listen for incoming connections.
            listen_port: The port number where the proxy will listen for incoming connections.
            forward_from_ip: The IP address from which the proxy will forward data.
            forward_to_ip: The IP address to which the proxy will forward data.
            forward_to_port: The port number to which the proxy will forward data.
        """

        super().__init__()

        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.forward_from_ip = forward_from_ip
        self.forward_to_ip = forward_to_ip
        self.forward_to_port = forward_to_port
        self.fault_detected = False

        # socket listening for incoming connections
        self._server_socket: SocketT | None = None
        self._source = self._get_endpoint(PUBLISHER_SOURCE_NAME)

        # socket forwarding data to the target
        self._forward_socket: SocketT | None = None
        self._target = self._get_endpoint(PUBLISHER_TARGET_NAME)

    @abstractmethod
    def _get_endpoint(self, name: str) -> ProxyEndpoint[SocketT]:
        """Get an endpoint by its name.

        Args:
            name: The name of the endpoint.

        Returns:
            ProxyEndpoint[SocketT]: The endpoint with the given name.
        """

    @property
    def source(self) -> Publisher:
        """The source endpoint of the network proxy.

        The source endpoint is responsible for receiving data from and sending data to the client
        connecting to the network proxy.
        """

        return self._source

    @property
    def target(self) -> Publisher:
        """The target endpoint of the network proxy.

        The target endpoint is responsible for receiving data from and sending data to the server
        to which the network proxy forwards data to.
        """

        return self._target

    def _is_socket_open(self, sock: SocketT) -> bool:
        """Checks if a socket is open.

        Args:
            sock: The network socket to check.

        Returns:
            bool: `True` if the socket is open, `False` otherwise.
        """

        return sock.fileno() != -1

    @abstractmethod
    def _setup_target_socket(self) -> SocketT:
        """Setup the target socket for forwarding data.

        Returns:
            SocketT: The network socket for forwarding data to the target.
        """

    @abstractmethod
    def _setup_source_socket(self) -> SocketT:
        """Setup the source socket to listen for incoming connections.

        Returns:
            SocketT: The network socket for listening for incoming connections.

        Raises:
            SocketError: If the `bind` socket function fails.
        """

    def _handle_connection(self, connection_socket: SocketT, peer_info: tuple[str, int]):
        """Handle a network connection.

        This function is responsible for managing a network connection between a client connecting
        to this proxy, and the network server to which the proxy will connect to.

        Args:
            connection_socket: The network socket representing the client connection to this proxy.
            peer_info: A tuple containing the IP address and port number of the client connected to
                this proxy.

        Raises:
            OSError: If some error occurs during the connection to the other peer.
        """

        logging.info("Accepted connection from %s", peer_info[0], extra={'entity': 'Proxy'})

        # setup target socket
        self._forward_socket = self._setup_target_socket()
        self._forward_socket.connect((self.forward_to_ip, self.forward_to_port))
        logging.info("Connected to forward server at %s:%s",
                     self.forward_to_ip, self.forward_to_port, extra={'entity': 'Proxy'})

        self._source.socket = connection_socket
        self._target.socket = self._forward_socket
        self._setup_endpoints()
        self._source.start()
        self._target.start()

        while not self.stop_event.is_set() \
                and self._is_socket_open(self._forward_socket) \
                and self._is_socket_open(connection_socket):
            time.sleep(0.1)

        # close the connections and reset the endpoints
        try:
            self._target.stop()
            self._source.stop()
        except PublisherOperationError:
            self.fault_detected = True

        self._source.socket = self._target.socket = None
        self._forward_socket.close()
        connection_socket.close()
        logging.info("Closed connection to %s", peer_info[0], extra={'entity': 'Proxy'})

    def _check_required_parameters(self):
        """Check if required parameters are set.

        Raises:
            MissingConfigError: If one between `listen_ip`, `listen_port`, `forward_from_ip`,
                `forward_to_ip` and `forward_to_port` is not set.
        """

        if self.listen_ip is None or self.listen_port is None:
            raise MissingConfigError('Listen IP/port not specified')

        if self.forward_from_ip is None:
            raise MissingConfigError('IP from which to forward not specified')

        if self.forward_to_ip is None or self.forward_to_port is None:
            raise MissingConfigError('Destination IP/port not specified')

    @abstractmethod
    def _setup_endpoints(self):
        """Setup the endpoints for the network proxy.

        This function should initialize the source and target endpoints based on the provided
        configuration parameters.
        """

    @override
    def handled_run(self):
        """Start the network proxy.

        This function spin up a server listening for incoming connections on the interface
        `listen_ip` and the port `listen_port`. Each new incoming connection will be handled by the
        method `_handle_sctp_connection`.

        Raises:
            MissingConfigError: If one between `listen_ip`, `listen_port`, `forward_from_ip`,
                `forward_to_ip` and `forward_to_port` is not set.
            SocketError: If either the `bind`, `listen`, or `accept` socket function fails.
        """

        self._check_required_parameters()

        # setup source server socket
        self._server_socket = self._setup_source_socket()

        logging.info("Starting proxy on %s:%s",
                     self.listen_ip, self.listen_port, extra={'entity': 'Proxy'})
        logging.info("Forwarding to %s:%s from %s", self.forward_to_ip,
                     self.forward_to_port, self.forward_from_ip, extra={'entity': 'Proxy'})

        try:
            self._server_socket.listen(1)
        except OSError as e:
            msg = f"Error on listen: {e}"
            logging.error(msg, extra={'entity': 'Proxy'})
            self.is_error_recoverable = False
            raise SocketError(msg) from e

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
                raise SocketError(msg) from e
            try:
                self._handle_connection(client_socket, peer_info)
            except OSError as e:
                self._server_socket.close()
                msg = f"Error on connect: {e}"
                logging.error(msg, extra={'entity': 'Proxy'})
                self.is_error_recoverable = True
                raise SocketError(msg) from e

        self._server_socket.close()
        logging.info("Proxy stopped", extra={'entity': 'Proxy'})


class SCTPProxy(NetworkProxy[SctpSocketT]):
    """A specialized `NetworkProxy` that relays data over an SCTP socket."""

    @override
    def _get_endpoint(self, name: str) -> ProxyEndpoint[SocketT]:
        return SCTPProxyEndpoint(name)

    @override
    def _setup_target_socket(self) -> SocketT:
        sock = cast(SctpSocketT, sctp.sctpsocket_tcp(socket.AF_INET))
        sock.bind((self.forward_from_ip, 0))
        sock.events.peer_error = True
        sock.events.shutdown = True
        return sock

    @override
    def _setup_source_socket(self) -> SocketT:
        sock = cast(SctpSocketT, sctp.sctpsocket_tcp(socket.AF_INET))
        sock.sock().setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self.listen_ip, self.listen_port))
        except OSError as e:
            msg = f"Error on binding: {e}"
            logging.error(msg, extra={'entity': 'Proxy'})
            self.is_error_recoverable = False
            raise SocketError(msg) from e

        sock.settimeout(0.5)
        sock.events.peer_error = True
        sock.events.shutdown = True

        return sock

    @override
    def _setup_endpoints(self):
        cast(SCTPProxyEndpoint, self._source).endpoint_send_queue = self._target.send_queue
        cast(SCTPProxyEndpoint, self._target).endpoint_send_queue = self._source.send_queue


class NGAPProxy(SCTPProxy):
    """A specialized `NetworkProxy` that relays data over an NGAP transmission."""

    @override
    def _get_endpoint(self, name: str) -> ProxyEndpoint[SocketT]:
        return NGAPProxyEndpoint(name)

    @override
    def _setup_endpoints(self):
        super()._setup_endpoints()

        ngap_message_queue = Queue()
        cast(NGAPProxyEndpoint, self._source).ngap_queue = ngap_message_queue
        cast(NGAPProxyEndpoint, self._target).ngap_queue = ngap_message_queue


class NASMMProxy(NGAPProxy):
    """A specialized `NetworkProxy` that relays data over a NAS-MM transmission."""

    def __init__(self,
                 listen_ip: str,
                 listen_port: int,
                 forward_from_ip: str,
                 forward_to_ip: str,
                 forward_to_port: int,
                 op: str,
                 op_type: str,
                 key: str,
                 mcc: int,
                 mnc: int,
                 supi: str):
        """Initializes a new `NASMMProxy` instance.

        Args:
            listen_ip: The IP address where the proxy will listen for incoming connections.
            listen_port: The port number where the proxy will listen for incoming connections.
            forward_from_ip: The IP address from which the proxy will forward data.
            forward_to_ip: The IP address to which the proxy will forward data.
            forward_to_port: The port number to which the proxy will forward data.
            op: Operator code or Operator Code with Customization **in hexadecimal format**.
            op_type: Type of operator code (`'OP'` or `'OPC'`).
            key: Subscriber's key **in hexadecimal format**.
            mcc: Mobile Country Code.
            mnc: Mobile Network Code.
            supi: Subscription Permanent Identifier.
        """

        self._tr: NASSecurity = NASSecurity(op, op_type, key, mcc, mnc, supi)
        """Transformer to use for encryption/decryption of NAS-MM packets."""

        self._tr_lock: Lock = Lock()
        """Lock for the access to `_tr`."""

        super().__init__(listen_ip, listen_port, forward_from_ip, forward_to_ip, forward_to_port)

    @override
    def _get_endpoint(self, name: str) -> ProxyEndpoint[SocketT]:
        return NASMMProxyEndpoint(name, (self._tr, self._tr_lock))

    @override
    def _setup_endpoints(self):
        super()._setup_endpoints()

        nas_message_queue = Queue()
        cast(NASMMProxyEndpoint, self._source).nas_queue = nas_message_queue
        cast(NASMMProxyEndpoint, self._target).nas_queue = nas_message_queue


class PublisherProxyAgent(Publisher):
    """A class representing a `Publisher` that interacts with a network proxy.

    This class provides a bridge between the Publisher and the network proxy, allowing the
    Publisher to send and receive data through the proxy.
    """

    def __init__(self, pub_id: int, agent: "NetworkProxyAgent"):
        """Initialize a new `PublisherProxyAgent` instance.

        Args:
            pub_id: The unique identifier of the Publisher.
            agent: The network proxy agent that this Publisher interacts with .
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
class NetworkProxyAgent(GrpcClientAgent):
    """Agent that controls a network proxy."""

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
        """Get the source endpoint of the network proxy.

        The source endpoint is responsible for receiving data from and sending data to the client
        connecting to the network proxy.

        Returns:
            Publisher: An instance of `Publisher` representing the source endpoint.
        """

        return PublisherProxyAgent(PUBLISHER_SOURCE_ID, self)

    def get_target(self) -> Publisher:
        """Get the target endpoint of the network proxy.

        The target endpoint is responsible for receiving data from and sending data to the server
        to which the network proxy forwards data to.

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
                - `'listen'`: A dictionary with the following key - value pairs:
                    - `'ip'`: A string representing the IP address where the SCTP proxy will listen
                        on.
                    - `'port'`: A number representing the SCTP port where the proxy will listen on.
                - `'forward'`: A dictionary with the following key - value pairs:
                    - `'from_ip'`: A string representing the IP address from which the SCTP proxy
                        will forward data.
                    - `'to_ip'`: A string representing the IP address to which the SCTP proxy will
                        forward data.
                    - `'to_port'`: A number representing the SCTP port to which the proxy will
                        forward data.
                - `'restart_on_epoch'` (optional): Whether the proxy should be started and stopped 
                        respectively at the beginning and at the end of every epoch. Defaults to 
                        `False`.
                - `'restart_on_test'` (optional): Whether the proxy should be started and stopped 
                        respectively at the beginning and at the end of every test case or not. 
                        Defaults to `False`.
                - `'restart_on_redo'` (optional): Whether the proxy should be restarted before 
                        re-performing a test case or not. Defaults to `False`.
                - `'restart_on_fault'` (optional): Whether the proxy should be restarted at the end 
                        of a test case after a fault has been found or not (even if 
                        `restart_on_test` is set to `False`). Defaults to `False`.

                In case the proxy is used to fuzz the NAS-SM protocol, it must contain the 
                following additional keys:
                - `'sim'`: A dictionary with the following key - value pairs relative to data 
                    contained inside the SIM of the UE that will be connected to this proxy:
                    - `'op'`: Operator code or Operator Code with Customization **in hexadecimal format**.
                    - `'op_type'`: Type of operator code (`'OP'` or `'OPC'`).
                    - `'key'`: Subscriber's key **in hexadecimal format**.
                    - `'mcc'`: Mobile Country Code.
                    - `'mnc'`: Mobile Network Code.
                    - `'supi'`: Subscription Permanent Identifier.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method
                `stop_execution` is called.
        """

        super().set_options(**kwargs)

    @override
    def get_supported_paths(self, protocol: str) -> list[list[dict[str, str | bool]]]:
        return []

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        return []

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return False


class NetworkProxyServerAgent(GrpcServerAgent):
    """Server agent that controls a network proxy."""

    DEFAULT_OPTIONS: dict[str, str | int | bool | None] = {
        'listen_ip': None,
        'listen_port': None,
        'forward_from_ip': None,
        'forward_to_ip': None,
        'forward_to_port': None,
        'restart_on_epoch': False,
        'restart_on_test': False,
        'restart_on_redo': False,
        'restart_on_fault': False,
        'op': None,
        'op_type': None,
        'key': None,
        'mcc': None,
        'mnc': None,
        'supi': None
    }

    NGAP_OPTIONS = [
        'listen_ip', 'listen_port', 'forward_from_ip', 'forward_to_ip', 'forward_to_port']

    NAS_MM_OPTIONS = [
        'listen_ip', 'listen_port', 'forward_from_ip', 'forward_to_ip', 'forward_to_port']

    NAS_SM_OPTIONS = [
        'listen_ip', 'listen_port', 'forward_from_ip', 'forward_to_ip', 'forward_to_port',
        'op', 'op_type', 'key', 'mcc', 'mnc', 'supi']

    options: dict[str, str | int | bool | None]
    """Options currently set on the agent."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._proxy: SCTPProxy | None = None
        self._publisher_map: dict[int, Publisher] = {}

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._fault_detected: bool = False
        self._test_case_ctx: ExecutionContext = None

    @override
    def set_options(self, **kwargs):
        for key, val in kwargs.items():
            if key in {'listen', 'forward'}:
                for k, v in val.items():
                    local_key = key + '_' + k
                    if local_key not in self.options:
                        continue

                    self.options[local_key] = v
                    logging.info('Set %s[%s] = %s', key, k, v)
                continue

            if key == 'sim':
                for k, v in val.items():
                    if k not in self.options:
                        continue

                    self.options[k] = v
                    logging.info('Set %s[%s] = %s', key, k, v)
                continue

            if key not in self.options:
                continue

            self.options[key] = val
            logging.info('Set %s = %s', key, val)

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self._proxy = None
        self._publisher_map = {}
        self._fault_detected = False
        self._test_case_ctx = None

    def _start_procedure(self, ctx: ExecutionContext):
        """Start the network proxy based on the provided execution context.

        This method initializes and starts the appropriate network proxy instance
        based on the protocol specified in the execution context.

        Args:
            ctx: The execution context containing protocol-specific information required to 
                configure the proxy.

        Raises:
            AgentError: If:
                - The protocol specified in the execution context is unsupported.
                - Some required configuration parameters are missing.
                - An error occurswhile starting the proxy.
        """

        try:
            match ctx.protocol_name:
                case 'NGAP':
                    self._proxy = SCTPProxy(
                        **{k: v for k, v in self.options.items() if k in self.NGAP_OPTIONS})
                case 'NAS-MM':
                    self._proxy = NGAPProxy(
                        **{k: v for k, v in self.options.items() if k in self.NAS_MM_OPTIONS})
                case 'NAS-SM':
                    self._proxy = NASMMProxy(
                        **{k: v for k, v in self.options.items() if k in self.NAS_SM_OPTIONS})
                case _:
                    raise AgentError(f"Unsupported protocol: {ctx.protocol_name}")
        except TypeError as e:
            missing_args = str(e).split(': ')[1]
            missing_args = re.sub(r'\blisten_(\w+)', r'listen[\1]', missing_args)
            missing_args = re.sub(r'\bforward_(\w+)', r'forward[\1]', missing_args)
            raise AgentError(f"Missing required configuration: {missing_args}") from e

        self._publisher_map[PUBLISHER_SOURCE_ID] = self._proxy.source
        self._publisher_map[PUBLISHER_TARGET_ID] = self._proxy.target
        self._proxy.start()
        time.sleep(0.1)

        if self._proxy.is_error_occurred:
            self._publisher_map = {}
            self._proxy.join()
            raise AgentError(self._proxy.exception)

    def _stop_procedure(self):
        """Stop the network proxy and clean up resources.

        Raises:
            AgentError: If an error occurred while stopping the proxy or if the proxy
                encountered an unrecoverable error during its operation.
        """

        self._publisher_map = {}

        if self._proxy is None:
            return

        self._proxy.join()

        self._fault_detected = self._proxy.fault_detected

        if self._proxy.is_error_occurred:
            raise AgentError(self._proxy.exception)

        self._proxy = None

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        if self.options['restart_on_epoch']:
            self._start_procedure(ctx)

    @override
    def on_epoch_end(self):
        if self.options['restart_on_epoch'] and self._proxy is not None:
            self._stop_procedure()

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if (self.options['restart_on_test'] or self._fault_detected) and self._proxy is None:
            self._fault_detected = False
            self._start_procedure(ctx)

        self._test_case_ctx = ctx

    @override
    def on_test_end(self):
        if (self.options['restart_on_test'] or self._fault_detected) and self._proxy is not None:
            self._stop_procedure()

    @override
    def on_redo(self):
        if self.options['restart_on_redo'] and self._proxy is not None:
            self._stop_procedure()
            self._start_procedure(self._test_case_ctx)

    @override
    def on_fault(self):
        self._fault_detected = self.options['restart_on_fault']

    @override
    def fault_detected(self) -> bool:
        return self._fault_detected

    @override
    def redo_test(self) -> bool:
        return self._proxy is not None \
            and self._proxy.is_error_occurred \
            and self._proxy.is_error_recoverable

    @override
    def stop_execution(self) -> bool:
        return self._proxy is not None \
            and self._proxy.is_error_occurred \
            and not self._proxy.is_error_recoverable

    @override
    def on_shutdown(self):
        if self._proxy is not None:
            self._stop_procedure()

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


__all__ = ['NetworkProxyAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that relay packets on the machine.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="[%(entity)s][%(levelname)s] - %(message)s")

    class DefaultEntityFilter(logging.Filter):
        @override
        def filter(self, record):
            if not hasattr(record, 'entity'):
                record.entity = "Server"
            return True

    logging.getLogger("root").addFilter(DefaultEntityFilter())

    agent = NetworkProxyServerAgent(address=args.ip, port=args.port)

    agent.serve()
