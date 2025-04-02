from abc import abstractmethod
from dataclasses import dataclass
from typing import Generic, TypeVar, override, Any
from collections.abc import Callable, Iterator
from enum import Flag, auto

from more_itertools import first_true

from .mutator import Fuzzable, mutable
from .utils.graph import Graph, Node, Edge, Path
from .utils.register import ClassRegister

from .utils.errs import *


InnerT = TypeVar('InnerT', bound=Any)


@mutable
class Message(Fuzzable, Generic[InnerT]):
    """Entity which represents a message in a communication protocol.

    A `Message` is the content of the nodes of the protocol graph. It is also a `Fuzzable` entity 
    with the property that it has no parent.
    """

    delay: int
    """The number of seconds to wait before sending the message."""

    n_replay: int
    """The number of copies of this message to send."""

    @classmethod
    def from_name(cls, protocol: str, name: str, *args, **kwargs) -> "Message":
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
            return ClassRegister["Message"].get('Message', protocol, name)(*args, **kwargs)
        except ValueError as e:
            raise UnknownMessageError(f"Unknown message '{name}' in protocol '{protocol}'") from e

    def __init__(self, protocol: str, name: str = "", content: InnerT | None = None, delay: int = 0, n_replay: int = 1):
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

        self._content: InnerT | None = content
        self.delay = delay
        self.n_replay = n_replay

    @property
    def initialized(self) -> bool:
        """Whether the message has been initialized with some valid content or not."""

        return self._content is not None

    @override
    @property
    def name(self) -> str:
        """The name of the message."""

        return self._name

    @property
    def protocol(self) -> str:
        """The name of the protocol to which this message belongs."""

        return self._protocol

    @property
    def content(self) -> Any | None:
        """The content of the message."""

        return self._content

    @override
    @property
    def parent(self) -> Fuzzable | None:
        return None

    def __str__(self) -> str:
        return self.name

    @abstractmethod
    def parse(self, data: bytes) -> "Message":
        """Parse the given data into the message content.

        This method is responsible for interpreting the raw byte data and converting it into a 
        structured message format that can be used within the protocol.

        Args:
            data: The raw byte data to be parsed into the message content.

        Returns:
            Message: The parsed message object containing the structured content.

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


@dataclass(eq=False)
class ProtocolNode(Node):
    """A graph node specific for the `Protocol` class."""


@dataclass(eq=False)
class MessageNode(Node):
    """A graph node that contains a message."""

    src: str
    """The name of the actor that sends `msg`."""

    dst: str
    """The name of the actor that receives `msg`."""

    msg: Message
    """The message contained by this node."""


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


@dataclass(eq=False, init=False)
class ProtocolEdge(Edge[ProtocolNode]):
    """A graph edge specific for the `Protocol` class."""

    tags: EdgeTag
    """Tags for the edge which describe the relationship between `src` and `dst`."""

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
    """

    pos: int | None
    """The position of the edge in `path` whose `dst` node is the current node, or `None` if the 
    iteration isn't started yet."""

    actor: str | None
    """The name of the actor to be used in the path. If is `None`, then an iteration over this an 
    instance of this class returns all the nodes in the path regardless of who sent/received them."""

    optional: bool | None
    """Whether the current message is optional or not, or `None` if the iteration isn't started yet."""

    def __init__(self, path: list[ProtocolEdge], actor: str | None = None):
        """Initializes a new instance of the `ProtocolPath` class .

        Args:
            path: A list of edges that make up the path.
            actor (optional): The name of the actor to be used. Defaults to `None`.
        """

        super().__init__(path)

        self.pos = None
        self.optional = None
        self.actor = actor

    def _is_next(self, e: ProtocolEdge) -> bool:
        """Checks if the current edge contains the next node in to be visited."""

        return isinstance(e.dst, MessageNode) and (self.actor is None or self.actor in {e.dst.src, e.dst.dst})

    @property
    def next(self) -> MessageNode | None:
        """The next message in the path, or `None` if the iteration is finished."""

        path = self.path if self.pos is None else self.path[self.pos + 1:]
        res = first_true(path, default=None, pred=self._is_next)
        return res.dst if res is not None else None

    @property
    def names(self) -> list[str]:
        """The names of the messages inside the path."""

        res = []
        for edge in self.path:
            if isinstance(edge.dst, MessageNode) \
                    and (self.actor is None or self.actor in {edge.dst.src, edge.dst.dst}):
                res.append(edge.dst.msg.name)
        return res

    @property
    def optional_positions(self) -> set[int]:
        """The indexes of the messages that are optional inside the path."""

        return set(i for i, edge in enumerate(self.path) if EdgeTag.OPTIONAL in edge.tags)

    @override
    def __str__(self) -> str:
        actor = self.actor + ':' if actor is not None else ''
        return actor + '.'.join(str(edge.id) for edge in self.path)

    @override
    def __iter__(self) -> Iterator[MessageNode]:
        for pos, edge in enumerate(self.path):
            self.pos = pos
            self.optional = EdgeTag.OPTIONAL in edge.tags
            if self._is_next(edge):
                yield edge.dst
        self.pos = self.optional = None


class PathValidator:
    """A validator for checking if a sequence of messages matches a path."""

    def __init__(self, path: ProtocolPath):
        """Initializes a new `PathValidator` instance.

        Args:
            path: The path on which to validate incoming messages.
        """

        self._expected_sequence: list[MessageNode] = list(n for n in path)
        self._optional_positions: set[int] = path.optional_positions
        self._valid_positions: set[int] = {0}

    def process(self, msg: Message, src: str, dst: str) -> bool:
        """Processes a new message.

        Args:
            msg: The new message to be processed.
            src: The name of the actor that sent the message.
            dst: The name of the actor that received the message.

        Returns:
            bool: `True` if the message is valid and the sequence can continue, `False` otherwise.
        """

        next_positions: set[int] = set()

        for pos in self._valid_positions:
            stack = [pos]
            visited: set[int] = set()

            while stack:
                msg_idx = stack.pop()
                if msg_idx in visited:
                    continue
                visited.add(msg_idx)

                if msg_idx < len(self._expected_sequence) and msg_idx in self._optional_positions:
                    # skip optional message
                    stack.append(msg_idx + 1)

                if msg_idx < len(self._expected_sequence) \
                        and self._expected_sequence[msg_idx].msg.name == msg.name \
                        and self._expected_sequence[msg_idx].src == src \
                        and self._expected_sequence[msg_idx].dst == dst:
                    # the input message matches the expected message
                    next_positions.add(msg_idx + 1)

        if not next_positions:
            return False  # no valid way to continue

        self._valid_positions = next_positions
        return True

    def is_complete(self) -> bool:
        """Checks if the expected sequence has been fully respected, considering optional elements.

        Returns:
            bool: `True` if the sequence is complete and valid, `False` otherwise.
        """

        for pos in self._valid_positions:
            idx = pos
            while idx < len(self._expected_sequence) and idx in self._optional_positions:
                idx += 1
            if idx == len(self._expected_sequence):
                return True
        return False

    def next_expected_messages(self) -> set[MessageNode]:
        """Get the names of the next possible valid messages based on the messages already processed.

        Returns:
            set[MessageNode]: The possible next messages.
        """

        next_inputs: set[MessageNode] = set()
        for pos in self._valid_positions:
            i = pos
            visited: set[int] = set()
            stack: list[int] = [i]
            while stack:
                msg_idx = stack.pop()
                if msg_idx in visited:
                    continue
                visited.add(msg_idx)
                if msg_idx < len(self._expected_sequence):
                    if msg_idx in self._optional_positions:
                        # skip optional element
                        stack.append(msg_idx + 1)
                    # add the possible next input
                    next_inputs.add(self._expected_sequence[msg_idx])
        return next_inputs


class Protocol(Graph[ProtocolNode, ProtocolEdge, ProtocolPath]):
    """The `Protocol` class represents a communication protocol.

    The `Protocol` class represents a communication protocol as a graph, where nodes represent
    messages and edges represent dependencies between messages. In particular, if there is an edge
    from a message A to message B, it means that message B can be sent only after message A.

    In a protocol there can be multiple actors, i.e. entities that can send/receive messages. They
    are uniquely identified by their names and characterize each message in the protocol. More
    precisely, for each message in the protocol must be specified the name of the actor that sends
    the message and the actor that receives the message.
    """

    name: str
    """The name of the protocol."""

    root: ProtocolNode
    """The root node of the protocol graph."""

    actors: list[str]
    """The names of all the actors involved in the protocol."""

    @classmethod
    def from_name(cls, name: str) -> "Protocol":
        """Create a new `Protocol` instance from the specified name.

        Args:
            name: The name of the protocol to instanciate.

        Returns:
            Protocol: An instance of the specified protocol.

        Raises:
            UnknownProtocolError: If no protocol with the given name exists.
        """

        try:
            return ClassRegister["Protocol"].get('Protocol', name)()
        except ValueError as e:
            raise UnknownProtocolError(f"Unknown protocol '{name}'") from e

    def __init__(self, name: str):
        """Initializes the `Protocol` instance with a given name and creates a root node.

        Args:
            name: The name of the new protocol.
        """

        super().__init__()

        self.name = name
        self.root = self.create_dummy()
        self.actors = []

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

    def build_path(self, records: list[dict[str, str | bool]]) -> ProtocolPath | None:
        """Build a valid path from a given list of message records.

        Args:
            records: A list of items, each of them representing a message. Each item must be a 
                dictionary in the following form:
                ```
                {
                    "name": str,
                    "src": str,
                    "dst": str,
                    "optional": bool
                }
                ```
                Where:
                - `"name"` is the name of a message.
                - `"src"` is the source actor of the message.
                - `"dst"` is the destination actor of the message.
                - `"optional"` indicates whether the message is optional or not.

        Returns:
            ProtocolPath | None: The new path, or `None` if the path is not a valid path in the 
                protocol.

        Raises:
            UnknownMessageError: If some message name does not correspond to a real message in the 
                protocol.
        """

        if not self.get_path(records):
            return None

        nodes: dict[int, MessageNode] = {}
        path: list[ProtocolEdge] = []
        src_node = ProtocolNode(0)
        for r in records:
            key = hash(r['name'] + r['src'] + r['dst']) % 2**64
            if key in nodes:
                dst_node = nodes[key]
            else:
                msg = Message.from_name(self.name, r['name'])
                dst_node = MessageNode(id=key, src=r['src'], dst=r['dst'], msg=msg)
                nodes[r['name'] + r['src'] + r['dst']] = dst_node

            tags = EdgeTag.SEQUENCE
            if r['optional']:
                tags |= EdgeTag.OPTIONAL

            edge = ProtocolEdge(src=src_node, dst=dst_node, tags=tags)
            path.append(edge)

            src_node = dst_node

        return ProtocolPath(path)

    def get_path(self, path: list[dict[str, str | bool]] | str) -> ProtocolPath | None:
        """Retrieve a path in the protocol graph.

        Args:
            path: It can be in 2 formats:
                1. A string representation in the format `"actor:id.id.id..."` where:
                    - `actor` is the name of an actor in the protocol.
                    - `id` is the id of an existing edge in the protocol.
                2. A list of items, each of them representing a message. Each item must be a 
                    dictionary in the following form:
                    ```
                    {
                        "name": str,
                        "src": str,
                        "dst": str,
                        "optional": bool
                    }
                    ```
                    Where:
                    - `"name"` is the name of a message.
                    - `"src"` is the source actor of the message.
                    - `"dst"` is the destination actor of the message.
                    - `"optional"` indicates whether the message is optional or not.
                    In this case the first path matching all the names is chosen.

        Returns:
            ProtocolPath | None: The path found, or `None` if no valid path exists.
        """

        if isinstance(path, str):
            return self._get_path_from_str(path)
        return self._get_path_from_list(path)

    def _get_path_from_str(self, path: str) -> ProtocolPath | None:
        """Retrieve a path from a given string representation.

        Args:
            path: A string representation in the format `"actor:id.id.id..."` where:
                - `actor` is the name of an actor in the protocol.
                - `id` is the id of an existing edge in the protocol.

        Returns:
            ProtocolPath | None: The path found, or `None` if no valid path exists.
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

    def _get_path_from_list(self, records: list[dict[str, str | bool]]) -> ProtocolPath | None:
        """Retrieve a path in the protocol graph based on a list of message records.

        Args:
            records: A list of items, each of them representing a message. Each item must be a 
                dictionary in the following form:
                ```
                {
                    "name": str,
                    "src": str,
                    "dst": str,
                    "optional": bool
                }
                ```
                Where:
                - `"name"` is the name of a message.
                - `"src"` is the source actor of the message.
                - `"dst"` is the destination actor of the message.
                - `"optional"` indicates whether the message is optional or not.

        Returns:
            ProtocolPath | None: The first valid path found, or `None` if no valid path exists 
                matching the sequence.
        """

        # this keeps track of the message index in the current recursive call
        msg_idx_stack = [0]

        def on_enter(_):
            return

        def skip_edge(edge: ProtocolEdge) -> bool:
            # if it is a MessageNode it has a message with a name that can be compared to
            return isinstance(edge.dst, MessageNode) \
                and (edge.dst.msg.name != records[msg_idx_stack[-1]]['name']
                     or (edge.dst.src != records[msg_idx_stack[-1]]['src'])
                     or (edge.dst.dst != records[msg_idx_stack[-1]]['dst'])
                     or (records[msg_idx_stack[-1]]['optional']
                         and EdgeTag.OPTIONAL not in edge.tags))

        def yield_path(edge: ProtocolEdge) -> bool:
            # prepare the stack for the next recursion
            msg_idx_stack.append(msg_idx_stack[-1])

            if isinstance(edge.dst, MessageNode):
                # since we know that edge.dst.msg.name == records[msg_idx_stack[-2]]['name']
                # (because otherwise we would have skipped this edge) we can increment the new
                # message index
                msg_idx_stack[-1] += 1

            # if we reached the last element of the records' list, if they are equal we finally
            # found a path
            return msg_idx_stack[-1] == len(records)

        def on_exit(_):
            # since if we enter in another recursion level, we always push something on the stack
            # (see yield_path), on the return we always need to pop something off the stack
            msg_idx_stack.pop()

        build_path = ProtocolPath

        return next(self._dfs_traversal(
            self.root, [], {}, 0, build_path, skip_edge, yield_path, on_enter, on_exit), None)


from .proto import *
from .mutators import *
