from abc import ABC, abstractmethod

from .utils.register import ClassRegister

from .utils.errs import *


class Publisher(ABC):
    """This class represents a way to send and/or receive data by some means.

    The `Publisher` class is an abstract base class created to allow exchange of data through some
    means. It provides a common interface for various publishers, such as TCP sockets, files, or
    message queues.

    Subclasses must implement the `start`, `stop`, `send`, `receive`, and `data_available` methods 
    to provide specific functionality.
    """

    @classmethod
    def from_name(cls, name: str, *args, **kwargs) -> "Publisher":
        """Create a new `Publisher` instance from the specified name.

        Args:
            name: The name of the publisher to instanciate.
            args: Additional positional arguments that will be passed directly to the constructor 
                of the specified publisher.
            kwargs: Additional keyword arguments that will be passed directly to the constructor of 
                the specified publisher.

        Returns:
            Publisher: An instance of the specified publisher.

        Raises:
            UnknownPublisherError: If no publisher with the given name exists.
        """

        try:
            return ClassRegister["Publisher"].get('Publisher', name)(*args, **kwargs)
        except ValueError as e:
            raise UnknownPublisherError(f"Unknown agent '{name}'") from e

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

    @abstractmethod
    def __hash__(self) -> int:
        pass


class PublisherSource:
    """A class that manages and provides access to multiple publishers associated with actors.

    The `PublisherSource` class serves as a container and manager for multiple `Publisher` 
    instances, each associated with a specific actor. It provides methods to retrieve the list of 
    actors and to get the `Publisher` instance for a given actor.

    This class is useful in scenarios where multiple actors need to communicate through different 
    publishers, and a centralized management of these publishers is required.
    """

    @property
    def actors(self) -> list[str]:
        """The list of actors associated with this publisher source."""

        return []

    def get(self, actor: str) -> Publisher | None:
        """Get the publisher associated with the given actor name.

        Args:
            actor: Name of the actor to get the publisher for.

        Returns:
            Publisher | None: An instance of `Publisher` if the actor specified is in the list of 
                associated actors (see `actors`), `None` otherwise.
        """

        return None


__all__ = ['Publisher', 'PublisherSource']
