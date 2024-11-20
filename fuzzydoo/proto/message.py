from abc import abstractmethod
from typing import Any

from ..mutator import Fuzzable
from ..mutator import mutable
from ..utils.errs import FuzzyDooError
from ..utils.register import ClassRegister


class MessageError(FuzzyDooError):
    """Generic error for the `Message` interface."""


class UnknownMessageError(MessageError):
    """Exception raised when an unknown message type is encountered."""


class MessageParsingError(MessageError):
    """Exception raised when an error occurs while parsing a message."""


@mutable
class Message(Fuzzable):
    """Entity which represents a message in a communication protocol.

    A `Message` is the content of the nodes of the protocol graph. It is also a `Fuzzable` entity 
    with the property that it has no parent.

    Attributes:
        delay: The number of seconds to wait before sending the message.
        n_replay: The number of copies of this message to send.
    """

    @classmethod
    def from_name(cls, protocol: str, name: str) -> "Message":
        """Create a new `Message` instance from the specified names.

        Args:
            protocol: The name of the protocol the message belongs to.
            name: The name of the message to instanciate.

        Returns:
            Message: An instance of the specified message.

        Raises:
            UnknownMessageError: If no message with the given name exists in the given protocol.
        """

        try:
            return ClassRegister["Message"].get('Message', protocol, name)()
        except ValueError as e:
            raise UnknownMessageError(
                f"Unknown message '{name}' in protocol '{protocol}'") from e

    def __init__(self, protocol: str, name: str = "", content: Fuzzable | None = None, delay: int = 0, n_replay: int = 1):
        """Initialize a `Message` object.

        Args:
            protocol: The name of the protocol to which this message belongs.
            name (optional): The name of the message. Defaults to the class name.
            content (optional): The content of the message. Defaults to `None`.
            delay (optional): The number of seconds to wait before sending the message. Defaults to 
                `0`.
            n_replay (optional): The number of copies of this message to send. Defaults to `1`.
        """

        # assign the class name as the default name for the node
        self._name: str = name if name else self.__class__.__name__
        self._protocol: str = protocol

        self._content: Any | None = content
        self.delay: int = delay
        self.n_replay: int = n_replay

    @property
    def name(self) -> str:
        """Get the name of the message."""

        return self._name

    @property
    def protocol(self) -> str:
        """Get the name of the protocol to which this message belongs."""

        return self._protocol

    @property
    def content(self) -> Any | None:
        """Get the content of the message."""

        return self._content

    @property
    def parent(self) -> Fuzzable | None:
        return None

    def __str__(self) -> str:
        return self.name

    @abstractmethod
    def parse(self, data: bytes):
        """Parse the data into the message content.

        Raises:
            MessageParsingError: If the data cannot be parsed into a fuzzable object.
        """

        raise MessageParsingError()

    @abstractmethod
    def raw(self) -> bytes:
        """Return the raw content of the message

        Returns:
            bytes: The raw content of the message.
        """
