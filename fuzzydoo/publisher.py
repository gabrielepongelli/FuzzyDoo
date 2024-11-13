from abc import ABC, abstractmethod

from .utils.errs import FuzzyDooError


class PublisherError(FuzzyDooError):
    """Generic error for the `Publisher` interface."""


class PublisherOperationError(PublisherError):
    """Exception raised when a publisher encounters an error during send/receive operations."""


class Publisher(ABC):
    """This class represents a way to send and/or receive data by some means.

    The `Publisher` class is an abstract base class created to allow exchange of data through some
    means. It provides a common interface for various publishers, such as TCP sockets, files, or
    message queues.

    Subclasses must implement the `start`, `stop`, `send`, `receive`, and `data_available` methods 
    to provide specific functionality.
    """

    @abstractmethod
    def start(self):
        """Set `Publisher` to a running state where it can send/receive new data.

        Change state such that `receive`/`receive` will work. For TCP this could be
        connecting to a remote host, for a file it might be opening the file handle.

        Raises:
            PublisherOperationError: If an error occurs while starting the publisher.
        """

    @abstractmethod
    def stop(self):
        """Set `Publisher` to a stopped state where it can't send/receive new data.

        Change state such that `send`/`receive` will not work. For TCP this could
        be closing a connection, for a file it might be closing the file handle.

        Raises:
            PublisherOperationError: If an error occurs while stopping the publisher. In this case 
                the publisher should be stopped with the force.
        """

    @abstractmethod
    def send(self, data: bytes):
        """Send some data to `Publisher`.

        Args:
            data: The data to be sent.

        Raises:
            PublisherOperationError: If an error occurs while sending data.
        """

    @abstractmethod
    def receive(self) -> bytes:
        """Receive some data from `Publisher`.

        Returns:
            bytes: The received data.

        Raises:
            PublisherOperationError: If an error occurs while receiving data.
        """

    @abstractmethod
    def data_available(self) -> bool:
        """Check if there is any data available for reading from `Publisher`.

        Returns:
            bool: `True` if there is data available, `False` otherwise.

        Raises:
            PublisherOperationError: If an error occurs while checking data availability.
        """


__all__ = ['Publisher', 'PublisherError', 'PublisherOperationError']
