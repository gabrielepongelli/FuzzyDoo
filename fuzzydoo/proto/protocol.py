from dataclasses import dataclass
from typing import override
from collections.abc import Callable, Iterator
from enum import Flag, auto

from .message import Message
from ..utils.graph import Graph, Node, Edge, Path


class ProtocolError(Exception):
    """Generic error for the `Protocol` class."""


class InvalidPathError(ProtocolError):
    """Error raised when the provided path is invalid."""


@dataclass
class ProtocolNode(Node):
    """A graph node specific for the `Protocol` class.

    Attributes:
        id: The unique identifier for the node.
        msg: The message contained by this node.
        src: The name of the actor that sends `msg`.
        dst: The name of the actor that receives `msg`.
    """

    src: str
    dst: str
    msg: Message


class EdgeTag(Flag):
    """Enumeration of possible tags for edges in a `Protocol` graph.

    Each tag represents a type of dependency or relationship between messages
    in a communication protocol.
    """

    CONTROL_FLOW = auto()
    """Indicates a control flow dependency, where the destination message
    requires the source message to be completed before proceeding."""

    DATA_DEPENDENCY = auto()
    """Represents a data dependency, meaning the destination message depends
    on data generated or transformed by the source message."""

    ACKNOWLEDGEMENT = auto()
    """Shows that the destination message is an acknowledgment or receipt
    confirmation for the source message."""

    ERROR_HANDLING = auto()
    """Indicates that the destination message is an error-handling response,
    reacting to an error in the source message."""

    TIMEOUT = auto()
    """Specifies that the destination message will be sent if no response is
    received for the source message within a specified timeframe."""

    RETRY = auto()
    """Indicates a retry attempt, meaning the destination message is a
    retry following the failure of the source message."""

    SEQUENCE = auto()
    """Indicates a general sequential dependency, where the destination message
    logically follows the source message."""

    OPTIONAL = auto()
    """Specifies that the destination message is optional and may or may not
    occur after the source message."""


@dataclass
class ProtocolEdge(Edge[ProtocolNode]):
    """A graph edge specific for the `Protocol` class.

    Attributes:
        id: The unique identifier for the edge.
        src: The source node of the edge.
        dst: The destination node of the edge.
        tags: Tags for the edge which describe the relationship between `src` and `dst`.
    """

    tags: EdgeTag


@dataclass
class ProtocolPath(Path[ProtocolNode, ProtocolEdge]):
    """A class representing a path in the protocol graph.

    This class extends the `Path` class from the `utils.graph` module and is specifically designed
    to represent paths in the graph of the `Protocol` class taking into account the perspective of
    a specific actor.

    An iteration over this type returns all the messages in the path that are either sent by or
    received from the actor specified. All the other messages are skipped. The last message of the 
    path is always sent by the actor specified.

    Attributes:
        path: The list of edges that make up the path.
        actor: The name of the actor to be used in the path.
    """

    def __init__(self, path: list[ProtocolEdge], actor: str):
        """Initializes a new instance of the `ProtocolPath` class.

        Args:
            path: A list of edges that make up the path.
            pos (optional): The position of the edge in `path` whose `dst` node is the current node.
            actor: The name of the actor to be used.
        """

        super().__init__(path)

        self.pos: int | None = None
        self.actor: str = actor

    @override
    def __str__(self) -> str:
        """Returns a string representation of the current path."""

        return self.actor + ':' + '.'.join(str(edge.id) for edge in self.path)

    @override
    def __iter__(self):
        self.pos = 0
        for edge in self.path:
            if self.actor is None or self.actor in (edge.dst.src, edge.dst.dst):
                yield edge.dst
                self.pos += 1
        self.pos = None


class Protocol(Graph[ProtocolNode, ProtocolEdge]):
    """The `Protocol` class represents a communication protocol.

    The `Protocol` class represents a communication protocol as a graph, where nodes represent
    messages and edges represent dependencies between messages. In particular, if there is an edge
    from a message A to message B, it means that message B can be sent only after message A.

    In a protocol there can be multiple actors, i.e. entities that can send/receive messages. They
    are uniquely identified by their names and characterize each message in the protocol. More
    precisely, for each message in the protocol must be specified the name of the actor that sends
    the message and the actor that receives the message.

    Attributes:
        name: The name of the protocol.
        root: The root node of the protocol graph.
        actors: The names of all the actors involved in the protocol.
    """

    def __init__(self, name: str):
        """Initializes the `Protocol` instance with a given name and creates a root node.

        Args:
            name: The name of the new protocol.
        """

        super().__init__()

        self.name: str = name

        # create a root node in the protocol tree
        self.root: Node = Node(0)
        self.add_node(self.root)

        self.actors: list[str] = []

    @override
    def add_node(self, node: ProtocolNode):
        """Add a node to the graph. This method is overloaded to automatically generate and assign
        an ID whenever a node is added.

        Args:
            node: Node to add to the protocol graph.
        """

        if node.id == 0:
            node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def create_node(self, msg: Message, src: str, dst: str) -> ProtocolNode:
        """Create a new `ProtocolNode` instance correctly initialized.

        Args:
            msg: The message contained by the new node.
            src: The name of the actor that sends `msg`.
            dst: The name of the actor that receives `msg`.

        Returns:
            ProtocolNode: The newly created `ProtocolNode` instance.
        """

        if src not in self.actors:
            self.actors.append(src)

        if dst not in self.actors:
            self.actors.append(dst)

        node = ProtocolNode(0, src, dst, msg)
        self.add_node(node)
        return node

    def connect(self, src: ProtocolNode, dst: ProtocolNode | None = None, tags: EdgeTag = EdgeTag.SEQUENCE):
        """Create a connection between the two messages of the protocol.

        Creates a connection between the source message and the destination message. The `Protocol`
        class maintains a top level node that all initial messages must be connected to.

        Examples:
            There are two ways to call this routine, with the destination message being specified:

                >>> proto = Protocol("Example")
                >>> n1 = proto.create_node(Message(), 'client', 'server')
                >>> n2 = proto.create_node(Message(), 'server', 'client')
                >>> proto.connect(n1, n2)

            or by specifying only the source message:

                >>> proto.connect(proto.create_node(Message(), 'client', 'server'))

            In this last case, `connect` will attach the supplied message to the root node.

        Args:
            src: Node of the source message to connect.
            dst (optional): Node of the destination message to connect.
            tags (optional): An arbitrary tag for the edge. Defaults to `EdgeTag.SEQUENCE`.

        Returns:
            ProtocolEdge: The new connection between `src` and `dst`.
        """

        if dst is None:
            dst = src
            src = self.root

        # create an edge between the two nodes and add it to the graph.
        edge = ProtocolEdge(src, dst, tags)
        self.add_edge(edge)

        return edge

    def iterate_as(self, actor: str, tag_filter: Callable[[EdgeTag], bool] | None = None) -> Iterator[ProtocolPath]:
        """Iterate over all the paths inside this protocol that starts from the root node.

        Args:
            actor: The name of the actor for whom the paths should be returned.
            tag_filter (optional): A function that takes a tag as input and returns `True` if edges 
                with the given tag can be present in the paths. Defaults to `lamnda _: True`.

        Yields:
            ProtocolPath: Paths for which at least the last node is sent by `actor`. 
        """

        if tag_filter is None:
            def tag_filter(_):
                return True
        yield from self._iterate_as_rec(self.root, [], actor, tag_filter)

    def _iterate_as_rec(self, node: ProtocolNode, path: list[ProtocolEdge], actor: str, tag_filter: Callable[[EdgeTag], bool]) -> Iterator[ProtocolPath]:
        """Recursive helper for `iterate_as`.

        Args:
            node: Current message that is being visited.
            path: List of edges along the path to the current message being visited.
            actor: The name of the actor for whom the paths should be returned.
            tag_filter: A function that takes a tag as input and returns `True` if edges with the 
                given tag can be present in the paths.

        Yields:
            ProtocolPath: Paths for which at least the last node is sent by `actor`. 
        """

        # keep track of the path as we fuzz through it, don't count the root node
        # we keep track of edges as opposed to nodes because if there is
        # more than one path through a set of given nodes we don't want any ambiguity

        # step through every edge from the current node
        for edge in self.edges_from(node):
            if not tag_filter(edge.tags):
                continue

            path.append(edge)
            current_node = self.nodes[edge.dst.id]

            if actor == edge.dst.src:
                # return the path only if at least the last node can be sent by the actor
                # otherwise what should we fuzz?
                yield ProtocolPath(path, actor)

            # recursively fuzz the remainder of the messages in the protocol graph.
            yield from self._iterate_as_rec(current_node, path, actor, tag_filter)

            # finished with the last message on the path, pop it off the path stack.
            path.pop()

    def build_path(self, path: str) -> ProtocolPath:
        """Build a path from a given string representation.

        Args:
            path: String representation of the path.

        Returns:
            ProtocolPath: The built path.

        Raises:
            InvalidPathError: If the provided string representation does not match with a possible
                path.
        """

        actor, path = path.split(':')
        ids = path.split(".")
        path_edges = []

        for i in ids:
            i = int(i)
            if i not in self.edges:
                raise InvalidPathError(f"Invalid path: '{path}'")

            path_edges.append(self.edges[i])

        return ProtocolPath(path_edges, actor)
