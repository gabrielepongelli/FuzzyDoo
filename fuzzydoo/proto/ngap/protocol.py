# pylint: disable=too-many-lines
# pyright: reportUndefinedVariable=false

from dataclasses import dataclass
from enum import Enum
from typing import override
from collections.abc import Callable, Iterator

from ..protocol import MessageNode, Protocol, EdgeTag, ProtocolEdge, ProtocolNode, ProtocolPath
from .messages import *


class CapabilityAction(Enum):
    """Enumeration of possible actions to perform given a capability."""

    ADD = 1
    """Add the capability to the set of unlocked capabilities."""

    REMOVE = 2
    """Remove the capability from the set of unlocked capabilities."""

    REQUIRE = 3
    """Check if the capability is part of the set of unlocked capabilities."""


@dataclass
class CapabilityNode(ProtocolNode):
    """A graph node that represents a capability action.

    Attributes:
        id: The unique identifier for the node.
        action: The action contained by this node.
        capability: The capability contained by this node.
    """

    action: CapabilityAction
    capability: str


class NGAPProtocol(Protocol):
    """A protocol with methods specialized for the NGAP Protocol.

    Attributes:
        name: The name of the protocol. Is set to `"NGAP"`.
        root: The root node of the protocol graph.
        actors: The names of all the actors involved in the protocol.
        capabilities: The list of possible capability values in the protocol.
    """

    def __init__(self):
        """Initializes the `NGAPProtocol` instance with all the nodes and edges required by the 
        NGAP Protocol.
        """

        super().__init__('NGAP')

        self.capabilities: list[str] = []
        self._init()

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

        def on_enter(_):
            return

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

        yield from self._dfs_traversal(
            self.root, [], {}, max_visits, build_path, skip_edge, yield_path, on_enter, on_exit)

    def _iterate_allowed_paths(self, allowed_paths: list[ProtocolPath], actor: str, tag_filter: Callable[[EdgeTag], bool]) -> Iterator[ProtocolPath]:
        for path in super()._iterate_allowed_paths(allowed_paths, actor, tag_filter):
            if self._check_capabilities(path):
                yield path

    @override
    def _build_path_from_names(self, names: list[str]) -> ProtocolPath | None:
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
                    and isinstance(curr_node, CapabilityNode) \
                    and isinstance(next_node, CapabilityNode) \
                    and prev_node == next_node:
                # to avoid infinite loops
                return True

            if isinstance(next_node, MessageNode) \
                    and next_node.msg.name != names[msg_idx_stack[-1]]:
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
                # since we know that edge.dst.msg.name == names[msg_idx_stack[-2]] (because
                # otherwise we would have skipped this edge) we can increment the new message index
                msg_idx_stack[-1] += 1
            elif isinstance(edge.dst, CapabilityNode):
                self._update_capabilities(caps_stack[-1], edge.dst)

            # if we reached the last element of the names' list, if they are equal we finally
            # found a path
            return msg_idx_stack[-1] == len(names)

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
        """Check if the given path is a valid path taking into account the capabilities required during its traversal.

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

    # pylint: disable=too-many-locals
    def _init(self):
        """Initialize the graph with all the nodes and edges required."""

        ############################################################################################
        #############               8.2 PDU Session Management Procedures             ##############
        ############################################################################################
        ###
        # 8.2.1 PDU Session Resource Setup
        ###
        # pylint: disable=undefined-variable
        pdu_session_resource_setup_request = self.create_message(
            PDUSessionResourceSetupRequestMessage(), src='AMF', dst='NG-RAN node')
        pdu_session_resource_setup_response = self.create_message(
            PDUSessionResourceSetupResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=pdu_session_resource_setup_request,
                     dst=pdu_session_resource_setup_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.2.2 PDU Session Resource Release
        ###

        # pylint: disable=undefined-variable
        pdu_session_resource_release_command = self.create_message(
            PDUSessionResourceReleaseCommandMessage(), src='AMF', dst='NG-RAN node')
        pdu_session_resource_release_response = self.create_message(
            PDUSessionResourceReleaseResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=pdu_session_resource_release_command,
                     dst=pdu_session_resource_release_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.2.3 PDU Session Resource Modify
        ###

        # pylint: disable=undefined-variable
        pdu_session_resource_modify_request = self.create_message(
            PDUSessionResourceModifyRequestMessage(), src='AMF', dst='NG-RAN node')
        pdu_session_resource_modify_response = self.create_message(
            PDUSessionResourceModifyResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=pdu_session_resource_modify_request,
                     dst=pdu_session_resource_modify_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.2.4 PDU Session Resource Notify
        ###

        # pylint: disable=undefined-variable
        pdu_session_resource_notify = self.create_message(
            PDUSessionResourceNotifyMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.2.5 PDU Session Resource Modify Indication
        ###

        # pylint: disable=undefined-variable
        pdu_session_resource_modify_indication = self.create_message(
            PDUSessionResourceModifyIndicationMessage(), src='NG-RAN node', dst='AMF')
        pdu_session_resource_modify_confirm = self.create_message(
            PDUSessionResourceModifyConfirmMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=pdu_session_resource_modify_indication,
                     dst=pdu_session_resource_modify_confirm,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ############################################################################################
        ##############               8.3 UE Context Management Procedures             ##############
        ############################################################################################

        ###
        # 8.3.1 Initial Context Setup
        ###

        # pylint: disable=undefined-variable
        initial_context_setup_request = self.create_message(
            InitialContextSetupRequestMessage(), src='AMF', dst='NG-RAN node')
        initial_context_setup_response = self.create_message(
            InitialContextSetupResponseMessage(), src='NG-RAN node', dst='AMF')
        initial_context_setup_failure = self.create_message(
            InitialContextSetupFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=initial_context_setup_request,
                     dst=initial_context_setup_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=initial_context_setup_request,
                     dst=initial_context_setup_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.3.2 UE Context Release Request (NG-RAN node initiated)
        ###

        # pylint: disable=undefined-variable
        ue_context_release_request = self.create_message(
            UEContextReleaseRequestMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.3.3 UE Context Release (AMF initiated)
        ###

        # pylint: disable=undefined-variable
        ue_context_release_command = self.create_message(
            UEContextReleaseCommandMessage(), src='AMF', dst='NG-RAN node')
        ue_context_release_complete = self.create_message(
            UEContextReleaseCompleteMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=ue_context_release_command,
                     dst=ue_context_release_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.3.4 UE Context Modification
        ###

        # pylint: disable=undefined-variable
        ue_context_modification_request = self.create_message(
            UEContextModificationRequestMessage(), src='AMF', dst='NG-RAN node')
        ue_context_modification_response = self.create_message(
            UEContextModificationResponseMessage(), src='NG-RAN node', dst='AMF')
        ue_context_modification_failure = self.create_message(
            UEContextModificationFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=ue_context_modification_request,
                     dst=ue_context_modification_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ue_context_modification_request,
                     dst=ue_context_modification_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.3.5 RRC Inactive Transition Report
        ###

        # pylint: disable=undefined-variable
        rrc_inactive_transition_repord = self.create_message(
            RRCInactiveTransitionReportMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.3.6 Connection Establishment Indication
        ###

        # pylint: disable=undefined-variable
        connection_establishment_indication = self.create_message(
            ConnectionEstablishmentIndicationMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.3.7 AMF CP Relocation Indication
        ###

        # pylint: disable=undefined-variable
        amf_cp_relocation_indication = self.create_message(
            AMFCPRelocationIndicationMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.3.8 RAN CP Relocation Indication
        ###

        # pylint: disable=undefined-variable
        ran_cp_relocation_indication = self.create_message(
            RANCPRelocationIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.3.9 Retrieve UE Information
        ###

        # pylint: disable=undefined-variable
        retrieve_ue_information = self.create_message(
            RetrieveUEInformationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.3.10 UE Information Transfer
        ###

        # pylint: disable=undefined-variable
        ue_information_transfer = self.create_message(
            UEInformationTransferMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.3.11 UE Context Suspend
        ###

        # pylint: disable=undefined-variable
        ue_context_suspend_request = self.create_message(
            UEContextSuspendRequestMessage(), src='NG-RAN node', dst='AMF')
        ue_context_suspend_response = self.create_message(
            UEContextSuspendResponseMessage(), src='AMF', dst='NG-RAN node')
        ue_context_suspend_failure = self.create_message(
            UEContextSuspendFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=ue_context_suspend_request,
                     dst=ue_context_suspend_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ue_context_suspend_request,
                     dst=ue_context_suspend_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.3.12 UE Context Resume
        ###

        # pylint: disable=undefined-variable
        ue_context_resume_request = self.create_message(
            UEContextResumeRequestMessage(), src='NG-RAN node', dst='AMF')
        ue_context_resume_response = self.create_message(
            UEContextResumeResponseMessage(), src='AMF', dst='NG-RAN node')
        ue_context_resume_failure = self.create_message(
            UEContextResumeFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=ue_context_resume_request,
                     dst=ue_context_resume_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ue_context_resume_request,
                     dst=ue_context_resume_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ############################################################################################
        #############               8.4 UE Mobility Management Procedures             ##############
        ############################################################################################

        ###
        # 8.4.1 Handover Preparation
        ###

        # pylint: disable=undefined-variable
        handover_required = self.create_message(
            HandoverRequiredMessage(), src='NG-RAN node', dst='AMF')
        handover_command = self.create_message(
            HandoverCommandMessage(), src='AMF', dst='NG-RAN node')
        handover_preparation_failure = self.create_message(
            HandoverPreparationFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=handover_required,
                     dst=handover_command,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=handover_required,
                     dst=handover_preparation_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.4.2 Handover Resource Allocation
        ###

        # pylint: disable=undefined-variable
        handover_request = self.create_message(
            HandoverRequestMessage(), src='AMF', dst='NG-RAN node')
        handover_request_acknowledge = self.create_message(
            HandoverRequestAcknowledgeMessage(), src='NG-RAN node', dst='AMF')
        handover_failure = self.create_message(
            HandoverFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=handover_request,
                     dst=handover_request_acknowledge,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=handover_request,
                     dst=handover_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.4.3 Handover Notification
        ###

        # pylint: disable=undefined-variable
        handover_notify = self.create_message(
            HandoverNotifyMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.4.4 Path Switch Request
        ###

        # pylint: disable=undefined-variable
        path_switch_request = self.create_message(
            PathSwitchRequestMessage(), src='NG-RAN node', dst='AMF')
        path_switch_request_acknowledge = self.create_message(
            PathSwitchRequestAcknowledgeMessage(), src='AMF', dst='NG-RAN node')
        path_switch_request_failure = self.create_message(
            PathSwitchRequestFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=path_switch_request,
                     dst=path_switch_request_acknowledge,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=path_switch_request,
                     dst=path_switch_request_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.4.5 Handover Cancellation
        ###

        # pylint: disable=undefined-variable
        handover_cancel = self.create_message(
            HandoverCancelMessage(), src='NG-RAN node', dst='AMF')
        handover_cancel_acknowledge = self.create_message(
            HandoverCancelAcknowledgeMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=handover_cancel,
                     dst=handover_cancel_acknowledge,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=handover_required,
                     dst=handover_cancel,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.4.6 Uplink RAN Status Transfer
        ###

        # pylint: disable=undefined-variable
        uplink_ran_status_transfer = self.create_message(
            UplinkRANStatusTransferMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.4.7 Downlink RAN Status Transfer
        ###

        # pylint: disable=undefined-variable
        downlink_ran_status_transfer = self.create_message(
            DownlinkRANStatusTransferMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.4.8 Handover Success
        ###

        # pylint: disable=undefined-variable
        handover_success = self.create_message(
            HandoverSuccessMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.4.9 Uplink RAN Early Status Transfer
        ###

        # pylint: disable=undefined-variable
        uplink_ran_early_status_transfer = self.create_message(
            UplinkRANEarlyStatusTransferMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.4.10 Downlink RAN Early Status Transfer
        ###

        # pylint: disable=undefined-variable
        downlink_ran_early_status_transfer = self.create_message(
            DownlinkRANEarlyStatusTransferMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        #####################               8.5 Paging Procedures             ######################
        ############################################################################################

        ###
        # 8.5.1 Paging
        ###

        # pylint: disable=undefined-variable
        paging = self.create_message(
            PagingMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.5.2 Multicast Group Paging
        ###

        # pylint: disable=undefined-variable
        multicast_group_paging = self.create_message(
            MulticastGroupPagingMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        ############               8.6 Transport of NAS Messages Procedures             ############
        ############################################################################################

        ###
        # 8.6.1 Initial UE Message
        ###

        # pylint: disable=undefined-variable
        initial_ue_message = self.create_message(
            InitialUEMessageMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.6.2 Downlink NAS Transport
        ###

        # pylint: disable=undefined-variable
        downlink_nas_transport = self.create_message(
            DownlinkNASTransportMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.6.3 Uplink NAS Transport
        ###

        # pylint: disable=undefined-variable
        uplink_nas_transport = self.create_message(
            UplinkNASTransportMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.6.4 NAS Non Delivery Indication
        ###

        # pylint: disable=undefined-variable
        nas_non_delivery_indication = self.create_message(
            NASNonDeliveryIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.6.5 Reroute NAS Request
        ###

        # pylint: disable=undefined-variable
        reroute_nas_request = self.create_message(
            RerouteNASRequestMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        ##############               8.7 Interface Management Procedures             ###############
        ############################################################################################

        ###
        # 8.7.1 NG Setup
        ###

        # pylint: disable=undefined-variable
        ng_setup_request = self.create_message(
            NGSetupRequestMessage(), src='NG-RAN node', dst='AMF')
        ng_setup_response = self.create_message(
            NGSetupResponseMessage(), src='AMF', dst='NG-RAN node')
        ng_setup_failure = self.create_message(
            NGSetupFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=ng_setup_request,
                     dst=ng_setup_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ng_setup_request,
                     dst=ng_setup_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.7.2 RAN Configuration Update
        ###

        # pylint: disable=undefined-variable
        ran_configuration_update = self.create_message(
            RANConfigurationUpdateMessage(), src='NG-RAN node', dst='AMF')
        ran_configuration_update_acknowledge = self.create_message(
            RANConfigurationUpdateAcknowledgeMessage(), src='AMF', dst='NG-RAN node')
        ran_configuration_update_failure = self.create_message(
            RANConfigurationUpdateFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=ran_configuration_update,
                     dst=ran_configuration_update_acknowledge,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ran_configuration_update,
                     dst=ran_configuration_update_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.7.3 AMF Configuration Update
        ###

        # pylint: disable=undefined-variable
        amf_configuration_update = self.create_message(
            AMFConfigurationUpdateMessage(), src='AMF', dst='NG-RAN node')
        amf_configuration_update_acknowledge = self.create_message(
            AMFConfigurationUpdateAcknowledgeMessage(), src='NG-RAN node', dst='AMF')
        amf_configuration_update_failure = self.create_message(
            AMFConfigurationUpdateFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=amf_configuration_update,
                     dst=amf_configuration_update_acknowledge,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=amf_configuration_update,
                     dst=amf_configuration_update_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.7.4 NG Reset
        ###

        # AMF initiated
        # pylint: disable=undefined-variable
        ng_reset_amf = self.create_message(
            NGResetMessage(), src='AMF', dst='NG-RAN node')
        ng_reset_acknowledge_amf = self.create_message(
            NGResetAcknowledgeMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=ng_reset_amf,
                     dst=ng_reset_acknowledge_amf,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        # NG-RAN node initiated
        # pylint: disable=undefined-variable
        ng_reset_ran = self.create_message(
            NGResetMessage(), src='NG-RAN node', dst='AMF')
        ng_reset_acknowledge_ran = self.create_message(
            NGResetAcknowledgeMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=ng_reset_ran,
                     dst=ng_reset_acknowledge_ran,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.7.5 Error Indication
        ###

        # AMF initiated
        # pylint: disable=undefined-variable
        error_indication_amf = self.create_message(
            ErrorIndicationMessage(), src='AMF', dst='NG-RAN node')

        # NG-RAN node initiated
        # pylint: disable=undefined-variable
        error_indication_ran = self.create_message(
            ErrorIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.7.6 AMF Status Indication
        ###

        # pylint: disable=undefined-variable
        amf_status_indication = self.create_message(
            AMFStatusIndicationMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.7.7 Overload Start
        ###

        # pylint: disable=undefined-variable
        overload_start = self.create_message(
            OverloadStartMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.7.8 Overload Stop
        ###

        # pylint: disable=undefined-variable
        overload_stop = self.create_message(
            OverloadStopMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        #############               8.8 Configuration Transfer Procedures             ##############
        ############################################################################################

        ###
        # 8.8.1 Uplink RAN Configuration Transfer
        ###

        # pylint: disable=undefined-variable
        uplink_ran_configuration_transfer = self.create_message(
            UplinkRANConfigurationTransferMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.8.2 Downlink RAN Configuration Transfer
        ###

        # pylint: disable=undefined-variable
        downlink_ran_configuration_transfer = self.create_message(
            DownlinkRANConfigurationTransferMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        ##########               8.9 Warning Message Transmission Procedures             ###########
        ############################################################################################

        ###
        # 8.9.1 Write-Replace Warning
        ###

        # pylint: disable=undefined-variable
        write_replace_warning_request = self.create_message(
            WriteReplaceWarningRequestMessage(), src='AMF', dst='NG-RAN node')
        write_replace_warning_response = self.create_message(
            WriteReplaceWarningResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=write_replace_warning_request,
                     dst=write_replace_warning_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.9.2 PWS Cancel
        ###

        # pylint: disable=undefined-variable
        pws_cancel_request = self.create_message(
            PWSCancelRequestMessage(), src='AMF', dst='NG-RAN node')
        pws_cancel_response = self.create_message(
            PWSCancelResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=pws_cancel_request,
                     dst=pws_cancel_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.9.3 PWS Restart Indication
        ###

        # pylint: disable=undefined-variable
        pws_restart_indication = self.create_message(
            PWSRestartIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.9.4 PWS Failure Indication
        ###

        # pylint: disable=undefined-variable
        pws_failure_indication = self.create_message(
            PWSFailureIndicationMessage(), src='NG-RAN node', dst='AMF')

        ############################################################################################
        ################               8.10 NRPPa Transport Procedures             #################
        ############################################################################################

        ###
        # 8.10.1 Downlink UE Associated NRPPa Transport
        ###

        # pylint: disable=undefined-variable
        downlink_ue_associated_nrppa_transport = self.create_message(
            DownlinkUEAssociatedNRPPaTransportMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.10.2 Uplink UE Associated NRPPa Transport
        ###

        # pylint: disable=undefined-variable
        uplink_ue_associated_nrppa_transport = self.create_message(
            UplinkUEAssociatedNRPPaTransportMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.10.3 Downlink Non-UE Associated NRPPa Transport
        ###

        # pylint: disable=undefined-variable
        downlink_non_ue_associated_nrppa_transport = self.create_message(
            DownlinkNonUEAssociatedNRPPaTransportMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.10.4 Uplink Non-UE Associated NRPPa Transport
        ###

        # pylint: disable=undefined-variable
        uplink_non_ue_associated_nrppa_transport = self.create_message(
            UplinkNonUEAssociatedNRPPaTransportMessage(), src='NG-RAN node', dst='AMF')

        ############################################################################################
        #####################               8.11 Trace Procedures             ######################
        ############################################################################################

        ###
        # 8.11.1 Trace Start
        ###

        # pylint: disable=undefined-variable
        trace_start = self.create_message(
            TraceStartMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.11.2 Trace Failure Indication
        ###

        # pylint: disable=undefined-variable
        trace_failure_indication = self.create_message(
            TraceFailureIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.11.3 Deactivate Trace
        ###

        # pylint: disable=undefined-variable
        deactivate_trace = self.create_message(
            DeactivateTraceMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.11.4 Cell Traffic Trace
        ###

        # pylint: disable=undefined-variable
        cell_traffic_trace = self.create_message(
            CellTrafficTraceMessage(), src='NG-RAN node', dst='AMF')

        ############################################################################################
        ###############               8.12 Location Reporting Procedures             ###############
        ############################################################################################

        ###
        # 8.12.1 Location Reporting Control
        ###

        # pylint: disable=undefined-variable
        location_reporting_control = self.create_message(
            LocationReportingControlMessage(), src='AMF', dst='NG-RAN node')

        ###
        # 8.12.2 Location Reporting Failure Indication
        ###

        # pylint: disable=undefined-variable
        location_reporting_failure_indication = self.create_message(
            LocationReportingFailureIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.12.3 Location Report
        ###

        # pylint: disable=undefined-variable
        location_report = self.create_message(
            LocationReportMessage(), src='NG-RAN node', dst='AMF')

        ############################################################################################
        ################               8.13 UE TNLA Binding Procedures             #################
        ############################################################################################

        ###
        # 8.13.1 UE TNLA Binding Release
        ###

        # pylint: disable=undefined-variable
        ue_tnla_binding_release_request = self.create_message(
            UETNLABindingReleaseRequestMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        #########               8.14 UE Radio Capability Management Procedures             #########
        ############################################################################################

        ###
        # 8.14.1 UE Radio Capability Info Indication
        ###

        # pylint: disable=undefined-variable
        ue_radio_capability_info_indication = self.create_message(
            UERadioCapabilityInfoIndicationMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.14.2 UE Radio Capability Check
        ###

        # pylint: disable=undefined-variable
        ue_radio_capability_check_request = self.create_message(
            UERadioCapabilityCheckRequestMessage(), src='AMF', dst='NG-RAN node')
        ue_radio_capability_check_response = self.create_message(
            UERadioCapabilityCheckResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=ue_radio_capability_check_request,
                     dst=ue_radio_capability_check_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.14.3 UE Radio Capability ID Mapping
        ###

        # pylint: disable=undefined-variable
        ue_radio_capability_id_mapping_request = self.create_message(
            UERadioCapabilityIDMappingRequestMessage(), src='NG-RAN node', dst='AMF')
        ue_radio_capability_id_mapping_response = self.create_message(
            UERadioCapabilityIDMappingResponseMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=ue_radio_capability_id_mapping_request,
                     dst=ue_radio_capability_id_mapping_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ############################################################################################
        ##############               8.15 Data Usage Reporting Procedures             ##############
        ############################################################################################

        ###
        # 8.15.1 Secondary RAT Data Usage Report
        ###

        # pylint: disable=undefined-variable
        secondary_rat_data_usage_report = self.create_message(
            SecondaryRATDataUsageReportMessage(), src='NG-RAN node', dst='AMF')

        ############################################################################################
        ############               8.16 RIM Information Transfer Procedures             ############
        ############################################################################################

        ###
        # 8.16.1 Uplink RIM Information Transfer
        ###

        # pylint: disable=undefined-variable
        uplink_rim_information_transfer = self.create_message(
            UplinkRIMInformationTransferMessage(), src='NG-RAN node', dst='AMF')

        ###
        # 8.16.2 Downlink RIM Information Transfer
        ###

        # pylint: disable=undefined-variable
        downlink_rim_information_transfer = self.create_message(
            DownlinkRIMInformationTransferMessage(), src='AMF', dst='NG-RAN node')

        ############################################################################################
        ##########               8.17 Broadcast Session Management Procedures             ##########
        ############################################################################################

        ###
        # 8.17.1 Broadcast Session Setup
        ###

        # pylint: disable=undefined-variable
        broadcast_session_setup_request = self.create_message(
            BroadcastSessionSetupRequestMessage(), src='AMF', dst='NG-RAN node')
        broadcast_session_setup_response = self.create_message(
            BroadcastSessionSetupResponseMessage(), src='NG-RAN node', dst='AMF')
        broadcast_session_setup_failure = self.create_message(
            BroadcastSessionSetupFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=broadcast_session_setup_request,
                     dst=broadcast_session_setup_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=broadcast_session_setup_request,
                     dst=broadcast_session_setup_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.17.2 Broadcast Session Modification
        ###

        # pylint: disable=undefined-variable
        broadcast_session_modification_request = self.create_message(
            BroadcastSessionModificationRequestMessage(), src='AMF', dst='NG-RAN node')
        broadcast_session_modification_response = self.create_message(
            BroadcastSessionModificationResponseMessage(), src='NG-RAN node', dst='AMF')
        broadcast_session_modification_failure = self.create_message(
            BroadcastSessionModificationFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=broadcast_session_modification_request,
                     dst=broadcast_session_modification_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=broadcast_session_modification_request,
                     dst=broadcast_session_modification_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.17.3 Broadcast Session Release
        ###

        # pylint: disable=undefined-variable
        broadcast_session_release_request = self.create_message(
            BroadcastSessionReleaseRequestMessage(), src='AMF', dst='NG-RAN node')
        broadcast_session_release_response = self.create_message(
            BroadcastSessionReleaseResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=broadcast_session_release_request,
                     dst=broadcast_session_release_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.17.4 Broadcast Session Release Required
        ###

        # pylint: disable=undefined-variable
        broadcast_session_release_required = self.create_message(
            BroadcastSessionReleaseRequiredMessage(), src='NG-RAN node', dst='AMF')

        ############################################################################################
        ##########               8.18 Multicast Session Management Procedures             ##########
        ############################################################################################

        ###
        # 8.18.1 Distribution Setup
        ###

        # pylint: disable=undefined-variable
        distribution_setup_request = self.create_message(
            DistributionSetupRequestMessage(), src='NG-RAN node', dst='AMF')
        distribution_setup_response = self.create_message(
            DistributionSetupResponseMessage(), src='AMF', dst='NG-RAN node')
        distribution_setup_failure = self.create_message(
            DistributionSetupFailureMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=distribution_setup_request,
                     dst=distribution_setup_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=distribution_setup_request,
                     dst=distribution_setup_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.18.2 Distribution Release
        ###

        # pylint: disable=undefined-variable
        distribution_release_request = self.create_message(
            DistributionReleaseRequestMessage(), src='NG-RAN node', dst='AMF')
        distribution_release_response = self.create_message(
            DistributionReleaseResponseMessage(), src='AMF', dst='NG-RAN node')
        self.connect(src=distribution_release_request,
                     dst=distribution_release_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.18.3 Multicast Session Activation
        ###

        # pylint: disable=undefined-variable
        multicast_session_activation_request = self.create_message(
            MulticastSessionActivationRequestMessage(), src='AMF', dst='NG-RAN node')
        multicast_session_activation_response = self.create_message(
            MulticastSessionActivationResponseMessage(), src='NG-RAN node', dst='AMF')
        multicast_session_activation_failure = self.create_message(
            MulticastSessionActivationFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=multicast_session_activation_request,
                     dst=multicast_session_activation_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=multicast_session_activation_request,
                     dst=multicast_session_activation_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 8.18.4 Multicast Session Deactivation
        ###

        # pylint: disable=undefined-variable
        multicast_session_deactivation_request = self.create_message(
            MulticastSessionDeactivationRequestMessage(), src='AMF', dst='NG-RAN node')
        multicast_session_deactivation_response = self.create_message(
            MulticastSessionDeactivationResponseMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=multicast_session_deactivation_request,
                     dst=multicast_session_deactivation_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 8.18.5 Multicast Session Update
        ###

        # pylint: disable=undefined-variable
        multicast_session_update_request = self.create_message(
            MulticastSessionUpdateRequestMessage(), src='AMF', dst='NG-RAN node')
        multicast_session_update_response = self.create_message(
            MulticastSessionUpdateResponseMessage(), src='NG-RAN node', dst='AMF')
        multicast_session_update_failure = self.create_message(
            MulticastSessionUpdateFailureMessage(), src='NG-RAN node', dst='AMF')
        self.connect(src=multicast_session_update_request,
                     dst=multicast_session_update_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=multicast_session_update_request,
                     dst=multicast_session_update_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ############################################################################################
        ##########################               Capabilities             ##########################
        ############################################################################################

        self.capabilities.append('Initial Setup and Connection')
        cap_req_initial_setup = self.create_capability(
            self.capabilities[0], CapabilityAction.REQUIRE)

        self.capabilities.append('UE Context Created')
        cap_req_ue_context = self.create_capability(
            self.capabilities[1], CapabilityAction.REQUIRE)
        self.connect(cap_req_initial_setup, cap_req_ue_context)
        self.connect(cap_req_ue_context, cap_req_initial_setup)
        cap_del_ue_context = self.create_capability(
            self.capabilities[1], CapabilityAction.REMOVE)
        self.connect(cap_del_ue_context, cap_req_initial_setup)

        self.capabilities.append('UE PDU Session Established')
        cap_req_pdu_session = self.create_capability(
            self.capabilities[2], CapabilityAction.REQUIRE)
        self.connect(cap_req_ue_context, cap_req_pdu_session)
        self.connect(cap_req_pdu_session, cap_req_ue_context)
        cap_del_pdu_session = self.create_capability(
            self.capabilities[2], CapabilityAction.REMOVE)
        self.connect(cap_del_pdu_session, cap_req_ue_context)

        self.capabilities.append('Broadcast Session Established')
        cap_req_broadcast_session = self.create_capability(
            self.capabilities[3], CapabilityAction.REQUIRE)
        self.connect(cap_req_pdu_session, cap_req_broadcast_session)
        self.connect(cap_req_broadcast_session, cap_req_pdu_session)
        cap_del_broadcast_session = self.create_capability(
            self.capabilities[3], CapabilityAction.REMOVE)
        self.connect(cap_del_broadcast_session, cap_req_initial_setup)

        self.capabilities.append('Multicast Session Established')
        cap_req_multicast_session = self.create_capability(
            self.capabilities[4], CapabilityAction.REQUIRE)
        self.connect(cap_req_broadcast_session, cap_req_multicast_session)
        self.connect(cap_req_multicast_session, cap_req_broadcast_session)
        cap_del_multicast_session = self.create_capability(
            self.capabilities[4], CapabilityAction.REMOVE)
        self.connect(cap_del_multicast_session, cap_req_broadcast_session)

        ############################################################################################
        #####################               Procedure Dependencies             #####################
        ############################################################################################

        # the NG Setup procedure must be the first, then all the others
        self.connect(src=ng_setup_request)
        self.connect(src=ng_setup_failure, dst=self.root)

        cap_add_initial_setup = self.create_capability(
            self.capabilities[0], CapabilityAction.ADD)
        self.connect(src=ng_setup_response,
                     dst=cap_add_initial_setup)
        self.connect(src=cap_add_initial_setup,
                     dst=cap_req_initial_setup)

        ###
        # Procedures dependant on the initial connection being established
        ###
        self.connect(src=cap_req_initial_setup, dst=paging,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=paging, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=multicast_group_paging,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=multicast_group_paging, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=ran_configuration_update,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ran_configuration_update_acknowledge,
                     dst=cap_req_initial_setup)
        self.connect(src=ran_configuration_update_failure,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=amf_configuration_update,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=amf_configuration_update_acknowledge,
                     dst=cap_req_initial_setup)
        self.connect(src=amf_configuration_update_failure,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=downlink_nas_transport,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=downlink_nas_transport,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=uplink_nas_transport,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=uplink_nas_transport, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=ng_reset_amf,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ng_reset_acknowledge_amf,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=ng_reset_ran,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ng_reset_acknowledge_ran, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup,
                     dst=location_reporting_failure_indication,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=location_reporting_failure_indication,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=error_indication_amf,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=error_indication_amf,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=error_indication_ran,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=error_indication_ran, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=amf_status_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=amf_status_indication, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=overload_start,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=overload_start,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=overload_stop,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=overload_stop, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=uplink_ran_configuration_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=uplink_ran_configuration_transfer,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=downlink_ran_configuration_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=downlink_ran_configuration_transfer,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=write_replace_warning_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=write_replace_warning_response,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=pws_cancel_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=pws_cancel_response,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=pws_restart_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=pws_restart_indication,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=pws_failure_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=pws_failure_indication, dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup,
                     dst=downlink_non_ue_associated_nrppa_transport,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=downlink_non_ue_associated_nrppa_transport,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup,
                     dst=uplink_non_ue_associated_nrppa_transport,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=uplink_non_ue_associated_nrppa_transport,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=ue_radio_capability_id_mapping_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=ue_radio_capability_id_mapping_response,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=uplink_rim_information_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=uplink_rim_information_transfer,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=downlink_rim_information_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=downlink_rim_information_transfer,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=multicast_session_activation_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=multicast_session_activation_failure,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=broadcast_session_setup_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=broadcast_session_setup_failure,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=handover_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=handover_request_acknowledge,
                     dst=cap_req_initial_setup)
        self.connect(src=handover_failure,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=handover_notify,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=handover_notify,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=downlink_ran_status_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=downlink_ran_status_transfer,
                     dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=downlink_ran_early_status_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=downlink_ran_early_status_transfer,
                     dst=cap_req_initial_setup)

        self.connect(src=cap_req_initial_setup, dst=initial_ue_message,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=initial_ue_message, dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=reroute_nas_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=reroute_nas_request, dst=cap_req_initial_setup)
        self.connect(src=cap_req_initial_setup, dst=initial_context_setup_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=initial_context_setup_failure,
                     dst=cap_req_initial_setup)

        cap_add_ue_context = self.create_capability(
            self.capabilities[1], CapabilityAction.ADD)
        self.connect(src=initial_context_setup_response,
                     dst=cap_add_ue_context)
        self.connect(src=cap_add_ue_context, dst=cap_req_ue_context)

        ###
        # Procedures dependant on the successful creation of a UE context
        ###
        self.connect(src=cap_req_ue_context, dst=ue_context_release_command,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_context_release_complete, dst=cap_del_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_context_release_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_context_release_request, dst=cap_del_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_context_modification_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_context_modification_response,
                     dst=cap_req_ue_context)
        self.connect(src=ue_context_modification_failure,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=rrc_inactive_transition_repord,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=rrc_inactive_transition_repord,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=connection_establishment_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=connection_establishment_indication,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=amf_cp_relocation_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=cap_req_ue_context, dst=cap_del_ue_context)
        self.connect(src=amf_cp_relocation_indication, dst=nas_non_delivery_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=nas_non_delivery_indication,
                     dst=cap_del_ue_context)

        self.connect(src=cap_req_ue_context, dst=ran_cp_relocation_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(
            src=ran_cp_relocation_indication, dst=cap_req_ue_context)
        self.connect(src=ran_cp_relocation_indication, dst=cap_del_ue_context)

        self.connect(src=cap_req_ue_context, dst=retrieve_ue_information,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=retrieve_ue_information,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_information_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_information_transfer,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_context_suspend_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(
            src=ue_context_suspend_response, dst=cap_req_ue_context)
        self.connect(src=ue_context_suspend_failure,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_context_resume_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_context_resume_response,
                     dst=cap_req_ue_context)
        self.connect(src=ue_context_resume_failure,
                     dst=cap_del_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_radio_capability_info_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_radio_capability_info_indication,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_radio_capability_check_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_radio_capability_check_response,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_radio_capability_id_mapping_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_radio_capability_id_mapping_response,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=nas_non_delivery_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=nas_non_delivery_indication,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=downlink_ue_associated_nrppa_transport,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=downlink_ue_associated_nrppa_transport,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=uplink_ue_associated_nrppa_transport,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=uplink_ue_associated_nrppa_transport,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=trace_start,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=trace_start, dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=trace_failure_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=trace_failure_indication,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=deactivate_trace,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=deactivate_trace, dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=cell_traffic_trace,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=cell_traffic_trace, dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=location_reporting_control,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=location_reporting_control,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=location_reporting_failure_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=location_reporting_failure_indication,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=location_report,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=location_report, dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_tnla_binding_release_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_tnla_binding_release_request,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=ue_radio_capability_info_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_radio_capability_info_indication,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=ue_radio_capability_check_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=ue_radio_capability_check_response,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=secondary_rat_data_usage_report,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=secondary_rat_data_usage_report,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=handover_required,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=handover_command, dst=cap_req_ue_context)
        self.connect(
            src=handover_preparation_failure, dst=cap_req_ue_context)
        self.connect(src=path_switch_request_failure,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=handover_cancel,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(
            src=handover_cancel_acknowledge, dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=uplink_ran_status_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=uplink_ran_status_transfer,
                     dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=handover_success,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=handover_success, dst=cap_req_ue_context)
        self.connect(src=cap_req_ue_context, dst=uplink_ran_early_status_transfer,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=uplink_ran_early_status_transfer,
                     dst=cap_req_ue_context)

        self.connect(src=cap_req_ue_context, dst=pdu_session_resource_setup_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=pdu_session_resource_setup_response,
                     dst=cap_req_ue_context, tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        cap_add_pdu_session = self.create_capability(
            self.capabilities[2], CapabilityAction.ADD)
        self.connect(src=pdu_session_resource_setup_response,
                     dst=cap_add_pdu_session)
        self.connect(src=cap_add_pdu_session, dst=cap_req_pdu_session)

        ###
        # Procedures dependant on the successful creation of a PDU session
        ###
        self.connect(src=cap_add_pdu_session, dst=pdu_session_resource_modify_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=pdu_session_resource_modify_response,
                     dst=cap_add_pdu_session)
        self.connect(src=pdu_session_resource_modify_request,
                     dst=pdu_session_resource_modify_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)

        self.connect(src=cap_add_pdu_session, dst=pdu_session_resource_release_command,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=pdu_session_resource_release_response,
                     dst=cap_del_pdu_session)

        self.connect(src=cap_add_pdu_session, dst=pdu_session_resource_notify,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=pdu_session_resource_notify, dst=cap_del_pdu_session)

        self.connect(src=cap_add_pdu_session, dst=pdu_session_resource_modify_indication,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=pdu_session_resource_modify_confirm,
                     dst=cap_add_pdu_session)

        self.connect(src=cap_add_pdu_session, dst=path_switch_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=path_switch_request_acknowledge,
                     dst=cap_add_pdu_session)

        cap_add_broadcast_session = self.create_capability(
            self.capabilities[3], CapabilityAction.ADD)
        self.connect(src=broadcast_session_setup_response,
                     dst=cap_add_broadcast_session)
        self.connect(src=cap_add_broadcast_session,
                     dst=cap_req_broadcast_session)

        ###
        # Procedures dependant on the successful creation of a broadcast session
        ###
        self.connect(src=cap_req_broadcast_session, dst=broadcast_session_modification_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=broadcast_session_modification_response,
                     dst=cap_req_broadcast_session)
        self.connect(src=broadcast_session_modification_failure,
                     dst=cap_req_broadcast_session)

        self.connect(src=cap_req_broadcast_session, dst=broadcast_session_release_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=broadcast_session_release_response,
                     dst=cap_del_broadcast_session)

        self.connect(src=cap_req_broadcast_session, dst=broadcast_session_release_required,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=broadcast_session_release_required,
                     dst=cap_del_broadcast_session)

        cap_add_multicast_session = self.create_capability(
            self.capabilities[4], CapabilityAction.ADD)
        self.connect(src=multicast_session_activation_response,
                     dst=cap_add_multicast_session)
        self.connect(src=cap_add_multicast_session,
                     dst=cap_req_multicast_session)

        ###
        # Procedures dependant on the successful creation of a multicast session
        ###
        self.connect(src=cap_req_multicast_session, dst=distribution_setup_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=distribution_setup_response,
                     dst=distribution_setup_failure)
        self.connect(src=broadcast_session_modification_failure,
                     dst=cap_req_multicast_session)

        self.connect(src=cap_req_multicast_session, dst=distribution_release_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=distribution_release_response,
                     dst=distribution_setup_failure)

        self.connect(src=cap_req_multicast_session, dst=multicast_session_deactivation_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=multicast_session_deactivation_response,
                     dst=cap_del_multicast_session)

        self.connect(src=cap_req_multicast_session, dst=multicast_session_update_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.CONTROL_FLOW)
        self.connect(src=multicast_session_update_response,
                     dst=distribution_setup_failure)
        self.connect(src=multicast_session_update_failure,
                     dst=cap_req_multicast_session)


__all__ = ['NGAPProtocol']
