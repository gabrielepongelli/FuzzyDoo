from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class Node:
    """This class represents a node in a graph data structure.

    Attributes:
        id: The unique identifier for the node.
    """

    id: int


@dataclass
class Edge:
    """This class represents an edge in a graph data structure.

    This class represents an edge that connects the node `src` to the node `dst`.

    Attributes:
        id: The unique identifier for the node.
        src: The source node of the edge.
        dst: The destination node of the edge.
    """

    def __init__(self, src: Node, dst: Node):
        """Initialize an instance of the Edge class.

        This constructor takes two parameters, `src` and `dst`, which represent 
        the source and destination nodes of the edge, respectively. The `id` 
        attribute of the edge is calculated as the sum of the bitwise left 
        shift of the `src` parameter by 32 bits and the `dst` parameter.

        Args:
            src: The source node of the edge.
            dst: The destination node of the edge.
        """

        self.id: int = (src.id << 32) + dst.id
        self.src: Node = src
        self.dst: Node = dst


class Path:
    """This class represents a path in a graph data structure.

    The `Path` class is a collection of edges that connect nodes in a specific 
    order. It provides methods to iterate over the path and retrieve the next 
    node in the path.


    Attributes:
        path: A list of edges that make up the path.
        start: The starting node of the path.
    """

    def __init__(self, path: List[Edge], start: Node | None = None):
        """Initializes a new instance of the Path class.

        Args:
            path: A list of edges that make up the path.
            start: The starting node of the path. If not provided, the starting 
                node is set to the source node of the first edge in the path.
        """

        self.path: List[Edge] = path
        self.start: Node = path[0].src if start is None else start

        # keeps track of the current edge in the iteration
        self._curr: int | None = None

    def __iter__(self):
        """Returns an iterator for the Path class."""

        for i, edge in enumerate(self.path):
            if edge.src == self.start:
                self._curr = i

        if self._curr is None:
            return None

        return self

    def __next__(self) -> Node | None:
        """Returns the next node in the path during iteration.

        Returns:
            Node | None: The next node in the path. If there are no more nodes, 
                returns `None`.
        """

        if self._curr is None:
            return None
        node = self.path[self._curr].dst

        self._curr += 1
        if self._curr >= len(self.path):
            self._curr = None

        return node


class Graph:
    """This class represents a graph data structure.

    The `Graph` class represents a graph data structure, which is a collection 
    of nodes and edges. It provides methods for adding, removing, and 
    manipulating nodes and edges.

    Attributes:
        id: Unique identifier for the graph.
        edges: Dictionary of edges in the graph, with the edge ID as key and 
            the relative Edge object as value.
        nodes: Dictionary of nodes in the graph, with the node ID as key and 
            the relative Node object as value.

    Examples:
        >>> graph = Graph(1)
        >>> node1 = Node(1)
        >>> node2 = Node(2)
        >>> edge = Edge(node1, node2)
        >>> graph.add_node(node1)
        >>> graph.add_node(node2)
        >>> graph.add_edge(edge)
        >>> print(graph.nodes)
        {1: <__main__.Node at 0x7f9c80076c40>, 2: <__main__.Node at 0x7f9c80076c70>}
        >>> print(graph.edges)
        {3758096384: <__main__.Edge at 0x7f9c80076ca0>}

        >>> graph.remove_edge(id=3758096384)
        >>> print(graph.edges)
        {}

        >>> graph.remove_node(id=1)
        >>> print(graph.nodes)
        {2: <__main__.Node at 0x7f9c80076c70>}

        >>> found_edge = graph.find_edge("id", 3758096384)
        >>> print(found_edge)
        <__main__.Edge at 0x7f9c80076ca0>

        >>> found_node = graph.find_node("id", 2)
        >>> print(found_node)
        <__main__.Node at 0x7f9c80076c70>

        >>> edges_from_node1 = graph.edges_from(node_id=1)
        >>> print(edges_from_node1)
        []

        >>> edges_to_node2 = graph.edges_to(node_id=2)
        >>> print(edges_to_node2)
        [<__main__.Edge at 0x7f9c80076ca0>]
    """

    def __init__(self, graph_id: int | None = None):
        """Initialize a new instance of the `Graph` class.

        This constructor initializes a new graph with an optional unique 
        identifier. It also initializes empty dictionaries for storing edges 
        and nodes.

        Args:
            graph_id: The unique identifier for the graph. Defaults to `None`.
        """

        self.id: int = graph_id
        self.edges: Dict[int, Edge] = {}
        self.nodes: Dict[int, Node] = {}

    def add_edge(self, edge: Edge):
        """Add a new edge to the graph. Ensures a node exists for both the 
        source and destination of the edge.

        Args:
            edge: New edge to add.
        """

        if self.find_node("id", edge.src) is not None \
                and self.find_node("id", edge.dst) is not None:
            self.edges[edge.id] = edge

        return self

    def add_node(self, node: Node):
        """Add a new node to the graph. Ensures a node with the same id does 
        not already exist in the graph.

        Args:
            node: New node to add.
        """

        if node.id not in self.nodes:
            self.nodes[node.id] = node

        return self

    def remove_edge(self, edge_id: int | None = None, src: int | None = None, dst: int | None = None):
        """Remove an edge from the graph.

        Examples:
            There are two ways to call this routine, with an edge id:

                >>> graph.remove_edge(id)

            or by specifying the edge source and destination::

                >>> graph.remove_edge(src=source, dst=destination)

        Args:
            edge_id: Identifier of the edge to remove from the graph.
            src: Source node of the edge to remove.
            dst: Destination node of the edge to remove.
        """

        if not edge_id:
            edge_id = (src << 32) + dst

        if edge_id in self.edges:
            del self.edges[edge_id]

        return self

    def remove_node(self, node_id: int):
        """Remove a node from the graph.

        Args:
            node_id: Identifier of the node to remove from the graph.
        """

        if node_id in self.nodes:
            del self.nodes[node_id]

        return self

    def edges_from(self, node_id: int) -> List[Edge]:
        """Enumerate the edges from the specified node.

        Args:
            node_id: Identifier of the node to enumerate edges from.

        Returns:
            List of edges from the specified node.
        """

        return [edge_value for edge_value in list(self.edges.values()) if edge_value.src == node_id]

    def edges_to(self, node_id: int) -> List[Edge]:
        """Enumerate the edges to the specified node.

        Args:
            node_id: Identifier of the node to enumerate edges.

        Returns:
            List of edges to the specified node.
        """

        return [edge_value for edge_value in list(self.edges.values()) if edge_value.dst == node_id]

    def find_edge(self, attr: str, value: Any) -> Edge | None:
        """Find and return the edge with the specified `attr` / `value` pair.

        Args:
            attr: Attribute name we are looking for.
            value: Value of attribute we are looking for.

        Returns:
            Edge, if `attr` / `value` pair is matched. `None` otherwise.
        """

        # if the attribute to search for is the id, simply return the edge from the internal hash.
        if attr == "id":
            return self.edges.get(value, default=None)

        for edge in list(self.edges.values()):
            if hasattr(edge, attr):
                if getattr(edge, attr) == value:
                    return edge

        return None

    def find_node(self, attr: str, value: Any) -> Node | None:
        """Find and return the node with the specified `attr` / `value` pair.

        Args:
            attr: Attribute name we are looking for.
            value: Value of attribute we are looking for.

        Returns:
            Node, if `attr` / `value` pair is matched. `None` otherwise.
        """

        # if the attribute to search for is the id, simply return the node from the internal hash.
        if attr == "id" and value in self.nodes:
            return self.nodes.get(value, default=None)

        # step through all the nodes looking for the given <attribute,value> pair.
        else:
            for node in list(self.nodes.values()):
                if hasattr(node, attr):
                    if getattr(node, attr) == value:
                        return node

        return None
