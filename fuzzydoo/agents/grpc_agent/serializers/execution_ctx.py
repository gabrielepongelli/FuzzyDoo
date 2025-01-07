from ....agent import ExecutionContext
from ..generated import agent_pb2
from .protocol import ProtocolPathSerializer


class ExecutionContextSerializer:
    """Serializer and deserializer specific for `ExecutionContext` objects."""

    # pylint: disable=no-member
    @staticmethod
    def serialize(ctx: ExecutionContext) -> agent_pb2.ExecutionContext:
        """Serialize the given `ExecutionContext` object into a protobuf message.

        Args:
            ctx: The `ExecutionContext` object to serialize.

        Returns:
            agent_pb2.ExecutionContext: The serialized `ExecutionContext` protobuf message.
        """

        res = agent_pb2.ExecutionContext(path=ProtocolPathSerializer.serialize(ctx.path))
        res.protocol_name = ctx.protocol_name
        return res

    @staticmethod
    def deserialize(ctx: agent_pb2.ExecutionContext) -> ExecutionContext:
        """Deserialize the given protobuf message into a `ExecutionContext` instance.

        Args:
            ctx: The protobuf message to deserialize.

        Returns:
            ExecutionContext: The deserialized `ExecutionContext`.

        Raises:
            DeserializationError: If the deserialization fails due to invalid message type of some 
                `MessageNode` in the path.
        """

        return ExecutionContext(ctx.protocol_name, ProtocolPathSerializer.deserialize(ctx.path))


__all__ = ["ExecutionContextSerializer"]
