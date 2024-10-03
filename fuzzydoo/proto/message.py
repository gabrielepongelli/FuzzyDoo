from abc import abstractmethod

from ..utils import Node
from ..fuzzable import Fuzzable


class MessageParsingError(Exception):
    """Exception raised when an error occurs while parsing a message."""


class Message(Node, Fuzzable):
    """Entity which represents a message in a communication protocol.

    A `Message` is a node of the protocol graph that can be either sent to or received by the 
    target. A `Message` is also a `Fuzzable` entity with the following properties:
    - Its `size` value is the `size` value of its content.
    - Its `bit_length` value is the `bit_length` value of its content.
    - It has no parent.

    Attributes:
        delay: The number of seconds to wait before sending the message.
        n_replay: The number of copies of this message to send.
    """

    def __init__(self, name: str = "", content: Fuzzable | None = None, delay: int = 0, n_replay: int = 1):
        """Initialize a `Message` object.

        Args:
            content (optional): The content of the message. Defaults to `None`.
            name (optional): The name of the message. Defaults to the class name.
            delay (optional): The number of seconds to wait before sending the message. Defaults to 
                `0`.
            n_replay: The number of copies of this message to send. Defaults to `1`.
        """

        # IDs will be managed by the Protocol
        super(Node).__init__(0)

        # assign the class name as the default name for the node
        self._name: str = name if name else self.__class__.__name__
        self._content: Fuzzable | None = content
        self.delay: int = delay
        self.n_replay: int = n_replay

    @property
    def name(self) -> str:
        """Get the name of the message."""

        return self._name

    @property
    def content(self) -> Fuzzable | None:
        """Get the content of the message."""

        return self._content

    @property
    def size(self) -> int:
        return self._content.size

    @property
    def bit_length(self) -> int:
        return self._content.bit_length

    @property
    def parent(self) -> Fuzzable | None:
        return None

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
