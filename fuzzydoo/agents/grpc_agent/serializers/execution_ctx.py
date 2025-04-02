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

        res = agent_pb2.ExecutionContext(
            path=ProtocolPathSerializer.serialize(ctx.path),
            epoch=ctx.epoch,
            protocol_name=ctx.protocol_name
        )

        if ctx.test_case is not None:
            res.test_case = ctx.test_case

        if ctx.mutation_path is not None:
            res.mutation_path = ctx.mutation_path

        if ctx.mutator is not None:
            res.mutator = ctx.mutator

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

        res = ExecutionContext(
            ctx.protocol_name,
            ctx.epoch,
            ProtocolPathSerializer.deserialize(ctx.path)
        )

        if ctx.HasField('test_case'):
            res.test_case = ctx.test_case
        if ctx.HasField('mutation_path'):
            res.mutation_path = ctx.mutation_path
        if ctx.HasField('mutator'):
            res.mutator = ctx.mutator
        return res


__all__ = ["ExecutionContextSerializer"]
