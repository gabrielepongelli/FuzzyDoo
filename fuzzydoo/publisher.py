from abc import ABC, abstractmethod
from dataclasses import dataclass

from .utils.errs import FuzzyDooError


class PublisherError(FuzzyDooError):
    """Exception raised when a publisher encounters an error during send/receive operations."""


class Publisher(ABC):
    """This class represents a way to send and/or receive data by some means.

    The `Publisher` class is an abstract base class created to allow exchange of data through some
    means. It provides a common interface for various publishers, such as TCP sockets, files, or
    message queues.

    Subclasses must implement the `start`, `stop`, `send`, `receive`, and `data_available` methods 
    to provide specific functionality.
    """

    @property
    @abstractmethod
    def started(self) -> bool:
        """Check if the `Publisher` is currently running (i.e., in a running state).

        Returns:
            bool: `True` if the `Publisher` is running, `False` otherwise.
        """

    @abstractmethod
    def start(self):
        """Set `Publisher` to a running state where it can send/receive new data.

        Change state such that `receive`/`receive` will work. For TCP this could be
        connecting to a remote host, for a file it might be opening the file handle.
        """

    @abstractmethod
    def stop(self):
        """Set `Publisher` to a stopped state where it can't send/receive new data.

        Change state such that `send`/`receive` will not work. For TCP this could
        be closing a connection, for a file it might be closing the file handle.
        """

    @abstractmethod
    def send(self, data: bytes):
        """Send some data to `Publisher`.

        Parameters:
            data: The data to be sent.

        Raises:
            PublisherError: If an error occurs while sending data.
        """

    @abstractmethod
    def receive(self) -> bytes | None:
        """Receive some data from `Publisher`.

        Returns:
            bytes: The received data, or `None` if no data is available.

        Raises:
            PublisherError: If an error occurs while receiving data.
        """

    @abstractmethod
    def data_available(self) -> bool:
        """Check if there is any data available for reading from `Publisher`.

        Returns:
            bool: `True` if there is data available, `False` otherwise.

        Raises:
            PublisherError: If an error occurs while checking data availability.
        """


@dataclass
class NetworkPublisher(Publisher):
    """This class represents a `Publisher` over a network. It is distinguished by an address and a 
    port.

    Attributes:
        address: The network address of the publisher.
        port: The network port of the publisher.
    """

    def __init__(self, address: str, port: int):
        """Initialize a new instance of `Publisher` with the given address and port.

        Args:
            address: The network address of the publisher.
            port: The network port of the publisher.
        """

        super().__init__()
        self.address = address
        self.port = port


__all__ = ['Publisher', 'PublisherError', 'NetworkPublisher']
