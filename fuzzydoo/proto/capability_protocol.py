from dataclasses import dataclass
from enum import Enum
from typing import override
from collections.abc import Callable, Iterator

from ..protocol import MessageNode, Protocol, EdgeTag, ProtocolEdge, ProtocolNode, ProtocolPath


class CapabilityAction(Enum):
    """Enumeration of possible actions to perform on capabilities within a `CapabilityProtocol`.

    This enum defines the fundamental operations that can be performed on capabilities: adding,
    removing, and requiring. These actions are used in conjunction with `CapabilityNodes` to model
    the flow of capabilities through a protocol graph.

    Actions:
        ADD: Represents the action of granting or adding a capability.
            When encountered, this action adds the associated capability to the current set of
            active capabilities.

        REMOVE: Represents the action of revoking or removing a capability.
            When encountered, this action removes the associated capability from the current set of
            active capabilities, if present.

        REQUIRE: Represents a checkpoint that requires a specific capability.
            When encountered, this action checks if the associated capability is present in the
            current set of active capabilities. If not, it may block further progress along that
            path in the protocol graph.
    """

    ADD = 1
    """Add the capability to the set of unlocked capabilities."""

    REMOVE = 2
    """Remove the capability from the set of unlocked capabilities."""

    REQUIRE = 3
    """Check if the capability is part of the set of unlocked capabilities."""


@dataclass(eq=False)
class CapabilityNode(ProtocolNode):
    """A specialized node in the protocol graph that represents a capability action.

    `CapabilityNode` extends `ProtocolNode` to model capability-related operations within a
    `CapabilityProtocol`. Each node represents a single action (see `CapabilityAction`) associated
    with a specific capability.
    """

    action: CapabilityAction
    """The capability action associated with this node. This determines how the node affects the
    capability state when encountered during protocol traversal."""

    capability: str
    """The specific capability that this node operates on."""


class CapabilityProtocol(Protocol):
    """A specialized protocol for managing and validating capability-based interactions.

    This class extends the base `Protocol` class to handle capability-related operations, including
    adding, removing, and requiring capabilities during protocol execution. It provides methods for
    creating capability nodes, iterating through valid paths based on capability constraints, and
    checking the validity of paths considering capability requirements.

    The `CapabilityProtocol` class introduces specialized methods for handling `CapabilityNode`
    instances and ensures that paths through the protocol graph adhere to the specified capability
    constraints. This allows for modeling complex permission-based or role-based interaction flows
    within the protocol.
    """

    capabilities: list[str]
    """The list of possible capability values in the protocol."""

    def __init__(self, name: str):
        """Initializes a new `CapabilityProtocol` instance.

        Args:
            name: The name of the new protocol.
        """

        super().__init__(name)

        self.capabilities = []

    def create_capability(self, capability: str, action: CapabilityAction) -> CapabilityNode:
        """Create a new `CapabilityNode` instance correctly initialized.

        Args:
            capability: The capability contained by the new node.
            action: The action contained by the new node.

        Returns:
            CapabilityNode: The newly created `CapabilityNode` instance.
        """

        node = CapabilityNode(0, action, capability)
        self.add_node(node)
        return node

    @override
    def _iterate_all_paths(self, actor: str,
                           tag_filter: Callable[[EdgeTag], bool],
                           max_visits: int) -> Iterator[ProtocolPath]:
        # stack of capabilities associated with the current node
        caps_stack: list[list[str]] = [[]]

        def skip_edge(edge: ProtocolEdge) -> bool:
            return not tag_filter(edge) \
                or (isinstance(edge.dst, CapabilityNode)
                    and edge.dst.action == CapabilityAction.REQUIRE
                    and edge.dst.capability not in caps_stack[-1])

        def yield_path(edge: ProtocolEdge) -> bool:
            # prepare the stack for the next recursion
            caps_stack.append(list(caps_stack[-1]))

            next_node = edge.dst
            if isinstance(next_node, MessageNode) and actor == next_node.src:
                # return the path only if at least the last node can be sent by the actor
                # otherwise what should we fuzz?
                return True

            if isinstance(next_node, CapabilityNode):
                self._update_capabilities(caps_stack[-1], next_node)

            return False

        def on_exit(_):
            # pop capabilities for this call on the stack
            caps_stack.pop()

        def build_path(path: list[ProtocolEdge]):
            return ProtocolPath(path, actor)

        on_enter = lambda _: None

        yield from self._dfs_traversal(
            self.root, [], {}, max_visits, build_path, skip_edge, yield_path, on_enter, on_exit)

    def _iterate_allowed_paths(self,
                               allowed_paths: list[ProtocolPath],
                               actor: str,
                               tag_filter: Callable[[EdgeTag], bool]) -> Iterator[ProtocolPath]:
        for path in super()._iterate_allowed_paths(allowed_paths, actor, tag_filter):
            if self._check_capabilities(path):
                yield path

    @override
    def _get_path_from_list(self, records: list[dict[str, str | bool]]) -> ProtocolPath | None:
        # this keeps track of the message index in the current recursive call
        msg_idx_stack = [0]

        # stack of capabilities associated with the current node
        caps_stack: list[list[str]] = [[]]

        # the previous current node in the recursion (initially we can't have one)
        prev_node: ProtocolNode | None = None

        def on_enter(path: list[ProtocolEdge]):
            # update the previous node
            nonlocal prev_node
            prev_node = None if len(path) == 0 else path[-1].src

        def skip_edge(edge: ProtocolEdge) -> bool:
            curr_node = edge.src
            next_node = edge.dst

            if isinstance(prev_node, CapabilityNode) \
                    and (not isinstance(curr_node, MessageNode)) \
                    and isinstance(next_node, CapabilityNode) \
                    and prev_node == next_node:
                # to avoid infinite loops
                return True

            if isinstance(prev_node, ProtocolNode) \
                    and isinstance(curr_node, ProtocolNode) \
                    and prev_node == curr_node:
                # to avoid infinite loops
                return True

            if isinstance(next_node, MessageNode) \
                    and (next_node.msg.name != records[msg_idx_stack[-1]]['name']
                         or (next_node.src != records[msg_idx_stack[-1]]['src'])
                         or (next_node.dst != records[msg_idx_stack[-1]]['dst'])
                         or (records[msg_idx_stack[-1]]['optional']
                             and EdgeTag.OPTIONAL not in edge.tags)):
                return True

            # if we don't have the required capability to visit the destination node, then skip
            if isinstance(next_node, CapabilityNode) \
                    and next_node.action == CapabilityAction.REQUIRE \
                    and next_node.capability not in caps_stack[-1]:
                return True

            return False

        def yield_path(edge: ProtocolEdge) -> bool:
            # prepare the stack for the next recursion
            msg_idx_stack.append(msg_idx_stack[-1])
            caps_stack.append(list(caps_stack[-1]))

            if isinstance(edge.dst, MessageNode):
                # since we know that edge.dst.msg.name == records[msg_idx_stack[-2]]['name']
                # (because otherwise we would have skipped this edge) we can increment the new
                # message index
                msg_idx_stack[-1] += 1
            elif isinstance(edge.dst, CapabilityNode):
                self._update_capabilities(caps_stack[-1], edge.dst)

            # if we reached the last element of the records' list, if they are equal we finally
            # found a path
            return msg_idx_stack[-1] == len(records)

        def on_exit(_):
            # since if we enter in another recursion level, we always push something on the stack
            # (see yield_path), on the return we always need to pop something off the stack
            msg_idx_stack.pop()
            caps_stack.pop()

        build_path = ProtocolPath

        return next(self._dfs_traversal(
            self.root, [], {}, 0, build_path, skip_edge, yield_path, on_enter, on_exit), None)

    def _update_capabilities(self, caps: list[str], node: CapabilityNode):
        """Update the capabilities based on the given node.

        Args:
            caps: The list of capabilities to update.
            node: The node to update the capabilities from.
        """

        if node.action == CapabilityAction.ADD:
            caps.append(node.capability)
        elif node.action == CapabilityAction.REMOVE:
            try:
                caps.remove(node.capability)
            except ValueError:
                pass

    def _check_capabilities(self, path: ProtocolPath) -> bool:
        """Check if the given path is a valid path taking into account the capabilities required 
        during its traversal.

        Args:
            path: Path to check.

        Returns:
            bool: `True` if `path` is valid, `False` otherwise.
        """

        caps = []
        for edge in path.path:
            node = edge.dst
            if not isinstance(node, CapabilityNode):
                continue

            if node.action == CapabilityAction.REQUIRE:
                if node.capability not in caps:
                    return False
            else:
                self._update_capabilities(caps, node)

        return True
