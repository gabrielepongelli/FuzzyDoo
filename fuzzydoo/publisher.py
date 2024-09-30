from abc import ABC, abstractmethod
from typing import Tuple, Concatenate, List, Any
from collections.abc import Callable
from dataclasses import dataclass


OnMessageCallback = Callable[Concatenate[bytes, ...], Any]


class Publisher(ABC):
    """This class represents a way to send and/or receive data by some means.

    The `Publisher` class is an abstract base class created to allow exchange of data through some
    means. It provides a common interface for various publishers, such as TCP sockets, files, or
    message queues, allowing users to register callback functions to be executed when new data is
    received.

    Subclasses must implement the `start`, `stop`, `send`, and `receive` methods to provide
    specific functionality.

    Attributes:
        callbacks: A list of tuples, where each tuple contains a callback function and its
            arguments.
    """

    def __init__(self):
        """Initialize a new instance of `MessageSource` with an empty list of callbacks."""

        self.callbacks: List[Tuple[OnMessageCallback, Tuple]] = []

    def on_message(self, cb: OnMessageCallback, args: Tuple):
        """Register a callback function to be called when new data is received.

        This method allows the user to register a callback function that will be invoked when new 
        data is available from a publisher. The callback function will be called with the 
        received data as its first argument, followed by any additional arguments provided when 
        registering the callback.

        Args:
            cb: The callback function to be called when new data is received. The function should 
                accept a `bytes` value as its first argument, and other optional arguments.
            args: Additional arguments to be passed to the callback function when it is invoked.
        """

        self.callbacks.append((cb, args))

    @ abstractmethod
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
        """

    @abstractmethod
    def receive(self) -> bytes:
        """Receive some data from `Publisher`.

        Returns:
            bytes: The received data.
        """


@dataclass
class Target(Publisher):
    """This class represents a target, i.e., a `Publisher` over a network. It is distinguished by 
    an address and a port.

    Attributes:
        address: The network address of the target.
        port: The network port of the target.
    """

    def __init__(self, address: str, port: int):
        """Initialize a new instance of `Target` with the given address and port.

        Args:
            address: The network address of the target.
            port: The network port of the target.
        """

        super().__init__()
        self.address = address
        self.port = port
