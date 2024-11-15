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
    """A graph node specific for the `Protocol` class."""


@dataclass
class MessageNode(Node):
    """A graph node that contains a message.

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
    """A graph edge specific for the `Protocol` class .

    Attributes:
        id: The unique identifier for the edge.
        src: The source node of the edge.
        dst: The destination node of the edge.
        tags: Tags for the edge which describe the relationship between `src` and `dst`.
    """

    tags: EdgeTag

    def __init__(self, src: ProtocolNode, dst: ProtocolNode, tags: EdgeTag):
        """Initializes a new instance of the `ProtocolEdge` class .

        Args:
            src: The source node of the edge.
            dst: The destination node of the edge.
            tags: Tags for the edge which describe the relationship between `src` and `dst`.
        """

        super().__init__(src, dst)
        self.tags = tags


class ProtocolPath(Path[ProtocolNode, ProtocolEdge]):
    """A class representing a path in the protocol graph.

    This class extends the `Path` class from the `utils.graph` module and is specifically designed
    to represent paths in the graph of the `Protocol` class taking into account the perspective of
    a specific actor.

    An iteration over an instance of this class returns all the messages in the path that are 
    either sent by or received from the actor specified. All the other messages are skipped. The 
    last message of the path is always sent by the actor specified.

    Attributes:
        path: The list of edges that make up the path.
        pos: The position of the edge in `path` whose `dst` node is the current node, or `None` if 
            the iteration isn't started yet.
        actor: The name of the actor to be used in the path. If is `None`, then an iteration over 
            this an instance of this class returns all the nodes in the path regardless of who 
            sent/received them.
    """

    def __init__(self, path: list[ProtocolEdge], actor: str | None = None):
        """Initializes a new instance of the `ProtocolPath` class .

        Args:
            path: A list of edges that make up the path.
            actor (optional): The name of the actor to be used. Defaults to `None`.
        """

        super().__init__(path)

        self.pos: int | None = None
        self.actor: str | None = actor

    @property
    def names(self) -> list[str]:
        """Get the names of the messages inside the path."""

        res = []
        for edge in self.path:
            if isinstance(edge.dst, MessageNode) \
                    and (self.actor is None or self.actor in (edge.dst.src, edge.dst.dst)):
                res.append(edge.dst.msg.name)
        return res

    @override
    def __str__(self) -> str:
        return self.actor + ':' + '.'.join(str(edge.id) for edge in self.path)

    @override
    def __iter__(self) -> Iterator[MessageNode]:
        for pos, edge in enumerate(self.path):
            self.pos = pos
            if isinstance(edge.dst, MessageNode) \
                    and (self.actor is None or self.actor in (edge.dst.src, edge.dst.dst)):
                yield edge.dst
        self.pos = None


class Protocol(Graph[ProtocolNode, ProtocolEdge, ProtocolPath]):
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
        self.root: ProtocolNode = self.create_dummy()
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

    def create_message(self, msg: Message, src: str, dst: str) -> MessageNode:
        """Create a new `MessageNode` instance correctly initialized.

        Args:
            msg: The message contained by the new node.
            src: The name of the actor that sends `msg`.
            dst: The name of the actor that receives `msg`.

        Returns:
            MessageNode: The newly created `MessageNode` instance.
        """

        if src not in self.actors:
            self.actors.append(src)

        if dst not in self.actors:
            self.actors.append(dst)

        node = MessageNode(0, src, dst, msg)
        self.add_node(node)
        return node

    def create_dummy(self) -> ProtocolNode:
        """Create a new dummy node.

        This can be useful to create better recursive graphs.

        Returns:
            ProtocolNode: The newly created dummy node.
        """

        node = ProtocolNode(0)
        self.add_node(node)
        return node

    def connect(self, src: ProtocolNode, dst: ProtocolNode | None = None, tags: EdgeTag = EdgeTag.SEQUENCE):
        """Create a connection between the two nodes of the protocol.

        Creates a connection between the source node and the destination node. The `Protocol`
        class maintains a top level node that all initial nodes must be connected to.

        Examples:
            There are two ways to call this routine, with the destination node being specified:

                >> > proto = Protocol("Example")
                >> > n1 = proto.create_dummy()
                >> > n2 = proto.create_dummy()
                >> > proto.connect(n1, n2)

            or by specifying only the source node:

                >> > proto.connect(proto.create_dummy())

            In this last case, `connect` will attach the supplied node to the root node.

        Args:
            src: Source node to connect.
            dst (optional): Destination node to connect.
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

    def iterate_as(self, actor: str,
                   tag_filter: Callable[[EdgeTag], bool] = lambda _: True,
                   allowed_paths: list[ProtocolPath] | None = None,
                   max_visits: int = 1) -> Iterator[ProtocolPath]:
        """Iterate over all the paths inside this protocol that starts from the root node.

        Args:
            actor: The name of the actor for whom the paths should be returned.
            tag_filter (optional): A function that takes a tag as input and returns `True` if edges
                with the given tag can be present in the paths. Defaults to `lambda _: True`.
            allowed_paths (optional): List of allowed `ProtocolPath` objects to consider for 
                iteration. If is not `None`, then `max_visits` won't be used. Defaults to `None`.
            max_visits (optional): Maximum times a node can be visited. If it is `0` it means no 
                limit. Defaults to `1`.

        Yields:
            ProtocolPath: Paths for which at least the last node is a `MessageNode` instance whose 
                message is sent by `actor`.
        """

        if allowed_paths is not None:
            yield from self._iterate_allowed_paths(allowed_paths, actor, tag_filter)
        else:
            yield from self._iterate_all_paths(actor, tag_filter, max_visits)

    def _iterate_all_paths(self, actor: str,
                           tag_filter: Callable[[EdgeTag], bool],
                           max_visits: int) -> Iterator[ProtocolPath]:
        """Iterate over all the paths inside this protocol that starts from the root node.

        Args:
            actor: The name of the actor for whom the paths should be returned.
            tag_filter: A function that takes a tag as input and returns `True` if edges
                with the given tag can be present in the paths.
            max_visits: Maximum times a node can be visited. If it is `0` it means no 
                limit.

        Yields:
            ProtocolPath: Paths for which at least the last node is a `MessageNode` instance whose 
                message is sent by `actor`.
        """

        def skip_edge(edge: ProtocolEdge) -> bool:
            return not tag_filter(edge)

        def yield_path(edge: ProtocolEdge) -> bool:
            return isinstance(edge.dst, MessageNode) and actor == edge.dst.src

        def on_enter(_):
            return

        def on_exit(_):
            return

        def build_path(path: list[ProtocolEdge]):
            return ProtocolPath(path, actor)

        yield from self._dfs_traversal(
            self.root, [], {}, max_visits, build_path, skip_edge, yield_path, on_enter, on_exit)

    def _iterate_allowed_paths(self, allowed_paths: list[ProtocolPath], actor: str, tag_filter: Callable[[EdgeTag], bool]) -> Iterator[ProtocolPath]:
        """Iterates over all unique subpaths in `allowed_paths`. Common subpaths are only yielded once.

        Args:
            allowed_paths: List of allowed `ProtocolPath` objects to consider for iteration.
            actor: The name of the actor for whom the paths should be returned.
            tag_filter: A function that takes a tag as input and returns `True` if edges with the 
                given tag can be present in the paths.

        Yields:
            ProtocolPath: Paths where at least the last node is a `MessageNode` sent by `actor`.
        """

        unique_paths = set()

        # generates all subpaths of a given path and adds them to the unique set
        def add_unique_subpaths(path: ProtocolPath):
            edges = path.path
            for end_idx in range(1, len(edges) + 1):
                subpath = ProtocolPath(edges[:end_idx])
                if subpath not in unique_paths:
                    unique_paths.add(subpath)
                    yield subpath

        for path in allowed_paths:
            for subpath in add_unique_subpaths(path):
                last_node = subpath.path[-1].dst
                if isinstance(last_node, MessageNode) and last_node.src == actor:
                    if all(tag_filter(edge.tags) for edge in subpath.path):
                        yield subpath

    def build_path(self, path: list[str] | str) -> ProtocolPath | None:
        """Build a path from a given string representation.

        Args:
            path: It can be in 2 formats:
                1. A string representation in the format "actor:id.id.id...".
                2. A list of message names. In this case the first path matching all the names is 
                    chosen.

        Returns:
            ProtocolPath: The built path.
            None: If no valid path exists.
        """

        if isinstance(path, str):
            return self._build_path_from_str(path)
        else:
            return self._build_path_from_names(path)

    def _build_path_from_str(self, path: str) -> ProtocolPath | None:
        """Build a path from a given string representation.

        Args:
            path: String representation of the path.

        Returns:
            ProtocolPath: The built path.
            None: If no valid path exists.
        """

        actor, path = path.split(':')
        ids = path.split(".")
        path_edges = []

        for i in ids:
            i = int(i)
            if i not in self.edges:
                return None

            path_edges.append(self.edges[i])

        return ProtocolPath(path_edges, actor)

    def _build_path_from_names(self, names: list[str]) -> ProtocolPath | None:
        """Build a path in the protocol graph based on a sequence of message names.

        Args:
            names: List of message names to search as a path.

        Returns:
            ProtocolPath: The first valid path if found.
            None: If no valid path exists matching the sequence.
        """

        # this keeps track of the message index in the current recursive call
        msg_idx_stack = [0]

        def on_enter(_):
            return

        def skip_edge(edge: ProtocolEdge) -> bool:
            # if it is a MessageNode it has a message with a name that can be compared to
            return isinstance(edge.dst, MessageNode) and edge.dst.msg.name != names[msg_idx_stack[-1]]

        def yield_path(edge: ProtocolEdge) -> bool:
            # prepare the stack for the next recursion
            msg_idx_stack.append(msg_idx_stack[-1])

            if isinstance(edge.dst, MessageNode):
                # since we know that edge.dst.msg.name == names[msg_idx_stack[-2]] (because
                # otherwise we would have skipped this edge) we can increment the new message index
                msg_idx_stack[-1] += 1

            # if we reached the last element of the names' list, if they are equal we finally
            # found a path
            return msg_idx_stack[-1] == len(names)

        def on_exit(_):
            # since if we enter in another recursion level, we always push something on the stack
            # (see yield_path), on the return we always need to pop something off the stack
            msg_idx_stack.pop()

        build_path = ProtocolPath

        return next(self._dfs_traversal(
            self.root, [], {}, 0, build_path, skip_edge, yield_path, on_enter, on_exit), None)
