from abc import ABC, abstractmethod

from .protocol import Message
from .utils.errs import FuzzyDooError
from .utils.register import ClassRegister


class TransformerError(FuzzyDooError):
    """Generic error for the `Transformer` interface."""


class TransformationError(TransformerError):
    """Error raised when a transformation operation fails."""


class EncodingError(TransformationError):
    """Error raised when an encoding operation fails."""


class DecodingError(TransformationError):
    """Error raised when a decoding operation fails."""


class UnknownTransformerError(TransformerError):
    """Exception raised when an unknown transformer type is encountered."""


class Transformer(ABC):
    """Abstract base class for message transformation operations.

    The `Transformer` class defines a common interface for objects that perform transformations on 
    `Message` objects. This can include operations such as encoding, decoding, encryption, 
    decryption, or any other form of message manipulation.

    Subclasses must implement the `transform` method to define the specific transformation logic.
    """

    @classmethod
    def from_name(cls, name: str, *args, **kwargs) -> "Transformer":
        """Create a new `Transformer` instance from the specified name.

        Args:
            name: The name of the transformer to instanciate.
            args: Additional positional arguments that will be passed directly to the constructor 
                of the specified transformer.
            kwargs: Additional keyword arguments that will be passed directly to the constructor of 
                the specified transformer.

        Returns:
            Transformer: An instance of the specified transformer.

        Raises:
            UnknownTransformerError: If no transformer with the given name exists.
        """

        try:
            return ClassRegister["Transformer"].get('Transformer', name)(*args, **kwargs)
        except ValueError as e:
            raise UnknownTransformerError(f"Unknown transformer '{name}'") from e

    @abstractmethod
    def transform(self, msg: Message, src: str, dst: str) -> Message:
        """Transform the given message.

        This abstract method defines the interface for message transformation operations.

        Args:
            msg: The message object to be transformed.
            src: The source entity from which the message originates.
            dst: The destination entity to which the message is being sent.

        Returns:
            Message: The transformed message object.

        Raises:
            TransformationError: If an error occurs during the transformation process.
        """

    @abstractmethod
    def reset(self):
        """Reset any internal state or resources used by the transformer.

        This method is called before starting a new transformation session. It can be useful for 
        clearing any temporary data or resources used during the transformation process.
        """


class Encoder(Transformer):
    """A specialized `Transformer` for encoding messages.

    The `Encoder` class extends the `Transformer` base class to provide a specific implementation 
    for encoding messages. It defines an additional `encode` method that wraps the `transform` 
    method, providing a more semantically appropriate interface for encoding operations.

    Subclasses should implement the `transform` method to define the specific encoding logic.
    """

    def encode(self, msg: Message, src: str, dst: str) -> Message:
        """Encode the given message.

        Args:
            msg: The message object to be encoded.
            src: The source entity from which the message originates.
            dst: The destination entity to which the message is being sent.

        Returns:
            Message: The encoded message object.

        Raises:
            EncodingError: If an error occurs during the encoding process.
        """

        try:
            return self.transform(msg, src, dst)
        except TransformationError as e:
            raise EncodingError(f"Failed to encode message: {str(e)}") from e


class Decoder(Transformer):
    """A specialized `Transformer` for decoding messages.

    The `Decoder` class extends the `Transformer` base class to provide a specific implementation 
    for decoding messages. It defines an additional `decode` method that wraps the `transform` 
    method, providing a more semantically appropriate interface for decoding operations.

    Subclasses should implement the `transform` method to define the specific decoding logic.
    """

    def decode(self, msg: Message, src: str, dst: str) -> Message:
        """Decode the given message.

        Args:
            msg: The message object to be decoded.
            src: The source entity from which the message originates.
            dst: The destination entity to which the message is being sent.

        Returns:
            Message: The decoded message object.

        Raises:
            DecodingError: If an error occurs during the decoding process.
        """

        try:
            return self.transform(msg, src, dst)
        except TransformationError as e:
            raise DecodingError(f"Failed to decode message: {str(e)}") from e


# so that all transformer classes are created
from .transformers import *
