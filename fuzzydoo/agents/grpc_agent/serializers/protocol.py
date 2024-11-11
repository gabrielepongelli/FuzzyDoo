from typing import override

from ....proto.message import Message, UnknownMessageError
from ....proto.protocol import EdgeTag, MessageNode, ProtocolEdge, ProtocolNode, ProtocolPath
from ..serializer import Serializer, DeserializationError
from ..generated import agent_pb2


class ProtocolNodeSerializer(Serializer[agent_pb2.ProtocolNode, ProtocolNode]):
    """Serializer and deserializer specific for `ProtocolNode` objects."""

    # pylint: disable=no-member
    @override
    @classmethod
    def serialize(cls, obj: ProtocolNode) -> agent_pb2.ProtocolNode:
        """Serialize the given `ProtocolNode` object into a protobuf message.

        Args:
            obj: The `ProtocolNode` object to serialize.

        Returns:
            agent_pb2.ProtocolNode: The serialized `ProtocolNode` protobuf message.
        """

        res = agent_pb2.ProtocolNode()
        res.id = obj.id

        if isinstance(obj, MessageNode):
            res.type = agent_pb2.ProtocolNode.Type.MESSAGE
            res.content.src = obj.src
            res.content.dst = obj.dst
            res.content.protocol_name = obj.msg.protocol
            res.content.msg_name = obj.msg.name
        else:
            res.type = agent_pb2.ProtocolNode.Type.DUMMY

        return res

    @override
    @classmethod
    def deserialize(cls, msg: agent_pb2.ProtocolNode) -> ProtocolNode:
        """Deserialize the given protobuf message into a `ProtocolNode` instance.

        Args:
            node: The protobuf message to deserialize.

        Returns:
            ProtocolNode: The deserialized `ProtocolNode`.

        Raises:
            DeserializationError: If the deserialization fails due to invalid message type.
        """

        if msg.type == agent_pb2.ProtocolNode.Type.DUMMY:
            res = ProtocolNode(msg.id)
        else:
            try:
                fuzzydoo_msg = Message.from_name(
                    msg.content.protocol_name, msg.content.msg_name)
            except UnknownMessageError as e:
                raise DeserializationError(
                    f"The message '{msg.content.msg_name}' doesn't exist "
                    f"inside the {msg.content.protocol_name} protocol") from e

            res = MessageNode(msg.id, msg.content.src,
                              msg.content.dst, fuzzydoo_msg)
        return res


class ProtocolEdgeSerializer(Serializer[agent_pb2.ProtocolEdge, ProtocolEdge]):
    """Serializer and deserializer specific for `ProtocolEdge` objects."""

    # pylint: disable=no-member
    @override
    @classmethod
    def serialize(cls, obj: ProtocolEdge) -> agent_pb2.ProtocolEdge:
        """Serialize the given `ProtocolEdge` object into a protobuf message.

        Args:
            obj: The `ProtocolEdge` object to serialize.

        Returns:
            agent_pb2.ProtocolEdge: The serialized `ProtocolEdge` protobuf message.
        """

        res = agent_pb2.ProtocolEdge(
            src=ProtocolNodeSerializer.serialize(obj.src),
            dst=ProtocolNodeSerializer.serialize(obj.dst),
            tags=obj.tags.value)

        return res

    @override
    @classmethod
    def deserialize(cls, msg: agent_pb2.ProtocolEdge) -> ProtocolEdge:
        """Deserialize the given protobuf message into a `ProtocolEdge` instance.

        Args:
            msg: The protobuf message to deserialize.

        Returns:
            ProtocolEdge: The deserialized `ProtocolEdge`.

        Raises:
            DeserializationError: This exception is raised:
                - If the deserialization fails due to invalid message type of one 
                    of the source or destination nodes.
                - If the `tags` field contains an invalid value.
        """

        tags = None
        for tag in EdgeTag:
            if tag.value & msg.tags:
                tags = tag if tags is None else tags | tag

        msg.tags = msg.tags ^ tags.value

        if tags is None or msg.tags != 0:
            raise DeserializationError("Invalid tags")

        return ProtocolEdge(ProtocolNodeSerializer.deserialize(msg.src),
                            ProtocolNodeSerializer.deserialize(msg.dst),
                            tags)


class ProtocolPathSerializer(Serializer[agent_pb2.ProtocolPath, ProtocolPath]):
    """Serializer and deserializer specific for `ProtocolPath` objects."""

    # pylint: disable=no-member
    @override
    @classmethod
    def serialize(cls, obj: ProtocolPath) -> agent_pb2.ProtocolPath:
        """Serialize the given `ProtocolPath` object into a protobuf message.

        Args:
            obj: The `ProtocolPath` object to serialize.

        Returns:
            agent_pb2.ProtocolPath: The serialized `ProtocolPath` protobuf message.
        """

        res = agent_pb2.ProtocolPath()
        res.path.extend([ProtocolEdgeSerializer.serialize(e)
                        for e in obj.path])
        return res

    @override
    @classmethod
    def deserialize(cls, msg: agent_pb2.ProtocolPath) -> ProtocolPath:
        """Deserialize the given protobuf message into a `ProtocolPath` instance.

        Args:
            msg: The protobuf message to deserialize.

        Returns:
            ProtocolPath: The deserialized `ProtocolPath`.

        Raises:
            DeserializationError: This exception is raised:
                - If the deserialization fails due to invalid message type of one of the source or 
                    destination nodes in one of the edges.
                - If the `tags` field of at least one edge contains an invalid value.
        """

        return ProtocolPath(
            path=[ProtocolEdgeSerializer.deserialize(e) for e in msg.path],
            actor=msg.actor if msg.HasField('actor') else None)


__all__ = ["ProtocolNodeSerializer",
           "ProtocolEdgeSerializer", "ProtocolPathSerializer"]
