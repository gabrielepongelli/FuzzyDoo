from typing import List

from .message import Message
from ..utils import Graph, Node, Edge, Path


class Protocol(Graph):
    """The `Protocol` class represents a communication protocol.

    The `Protocol` class represents a communication protocol as a graph, where nodes represent 
    messages and edges represent dependencies between messages. In particular, if there is an edge 
    from a message A to message B, it means that message B can be sent only after message A has 
    been sent.

    All the `Message` instances contained in this class are messages that should be sent to the 
    target (maybe after being fuzzed).

    Attributes:
        name: The name of the protocol.
        root: The root node of the protocol tree.
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

    def add_node(self, node: Node):
        """Add a node to the graph. This method is overloaded to automatically generate and assign 
        an ID whenever a node is added.

        Args:
            node: Node to add to the protocol graph.
        """

        node.id = len(self.nodes)

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def connect(self, src: Message, dst: Message | None = None) -> Edge:
        """Create a connection between the two messages of the protocol.

        Creates a connection between the source message and the destination message. The `Protocol` 
        class maintains a top level node that all initial messages must be connected to.

        Examples:
            There are two ways to call this routine, with the destination message being specified:

                >>> proto = Protocol("Sample")
                >>> proto.connect(proto.root, Message())

            or by specifying only the source message:

                >>> proto.connect(Message())

            In this last case, `connect` will attach the supplied message to the root node.

        Args:
            src: Source message to connect.
            dst (optional): Destination message to connect.

        Returns:
            Edge: The new connection between `src` and `dst`.
        """

        if dst is None:
            dst = src
            src = self.root

        # if src or dst is not in the graph, add it
        if src != self.root and self.find_node("name", src.name) is None:
            self.add_node(src)

        if self.find_node("name", dst.name) is None:
            self.add_node(dst)

        # create an edge between the two nodes and add it to the graph.
        edge = Edge(src.id, dst.id)
        self.add_edge(edge)

        return edge

    def __iter__(self):
        """Iterate over all the paths inside this protocol that starts from the root node.

        Returns:
            Protocol: The Protocol instance itself.
        """

        return self

    def __next__(self):
        """Advance to the next path in the iteration.

        Yields:
            Path: A list of edges representing a path from the root.
        """

        yield self._iterate_paths_rec(self.root, [])

    def _iterate_paths_rec(self, msg: Message, path: List[Edge]):
        """Recursive helper for `__next__`.

        Args:
            msg: Current message that is being visited.
            path: List of edges along the path to the current message being visited.

        Yields:
            Path: List of edges along the path to the current message being visited.
        """

        # step through every edge from the current message
        for edge in self.edges_from(msg.id):
            # keep track of the path as we fuzz through it, don't count the root node
            # we keep track of edges as opposed to nodes because if there is
            # more than one path through a set of given nodes we don't want any ambiguity
            path.append(edge)

            current_msg = self.nodes[edge.dst]
            yield Path(path)

            # recursively fuzz the remainder of the messages in the protocol graph.
            for x in self._iterate_paths_rec(current_msg, path):
                yield x

        # finished with the last message on the path, pop it off the path stack.
        if path:
            path.pop()
