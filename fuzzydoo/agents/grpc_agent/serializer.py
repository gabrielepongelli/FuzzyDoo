from abc import ABC, abstractmethod
from typing import TypeVar, Generic

from google.protobuf.message import Message

from ...utils.errs import *


class DeserializationError(FuzzyDooError):
    """Exception raised when deserialization fails."""


MessageT = TypeVar('MessageT', bound=Message)
ObjectT = TypeVar('ObjectT')


class Serializer(ABC, Generic[MessageT, ObjectT]):
    """Interface for serializers and deserializers of objects for protobuf classes."""

    @classmethod
    @abstractmethod
    def serialize(cls, obj: ObjectT) -> MessageT:
        """Serialize the given object into a protobuf message.

        Args:
            obj: The object to serialize.

        Returns:
            MessageT: The serialized protobuf message.
        """

    @classmethod
    @abstractmethod
    def deserialize(cls, msg: MessageT) -> ObjectT:
        """Deserialize the given protobuf message into a `ObjectT` instance.

        Args:
            msg: The protobuf message to deserialize.

        Returns:
            ObjectT: The deserialized `ObjectT` instance.

        Raises:
            DeserializationError: If the deserialization fails.
        """
