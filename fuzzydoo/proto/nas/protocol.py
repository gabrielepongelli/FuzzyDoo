# pyright: reportUndefinedVariable=false

from ...utils.register import register
from ...protocol import Protocol, EdgeTag
from ..capability_protocol import CapabilityProtocol, CapabilityAction

from .messages import *


@register(Protocol, 'NAS-MM', append_name=False)
class NASMMProtocol(CapabilityProtocol):
    """Represents the NAS-SM (Non-Access Stratum) protocol (Mobility Management subset) used in 5G networks.

    This class provides methods and attributes specific to the NAS-MM protocol, facilitating
    the management of various procedures such as PDU session management, UE context management,
    UE mobility management, and more.
    """

    def __init__(self):
        """Initializes the `NASMMProtocol` instance with all the nodes and edges required by the 
        NAS-MM protocol.
        """

        super().__init__('NAS-MM')
        self._init()

    # pylint: disable=too-many-locals
    def _init(self):
        """Initialize the graph with all the nodes and edges required."""

        ############################################################################################
        ##################               5.5 5GMM Specific Procedures             ##################
        ############################################################################################

        # checkpoint node for sub procedures
        fgmm_subprocedures = self.create_dummy()

        ###
        # 5.5.1 Registration Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_registration_request = self.create_message(
            FGMMRegistrationRequestMessage(), src='UE', dst='AMF')
        fgmm_registration_accept = self.create_message(
            FGMMRegistrationAcceptMessage(), src='AMF', dst='UE')
        fgmm_registration_complete = self.create_message(
            FGMMRegistrationCompleteMessage(), src='UE', dst='AMF')
        fgmm_registration_reject = self.create_message(
            FGMMRegistrationRejectMessage(), src='AMF', dst='UE')
        self.connect(src=fgmm_registration_request,
                     dst=fgmm_registration_accept,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_registration_accept,
                     dst=fgmm_registration_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_registration_request,
                     dst=fgmm_registration_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        self.connect(src=fgmm_registration_request,
                     dst=fgmm_subprocedures)
        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_registration_accept)
        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_registration_reject)

        ###
        # 5.5.2 De-Registration Procedure
        ###

        # UE initiated
        # pylint: disable=undefined-variable
        fgmm_deregistration_request_ue = self.create_message(
            FGMMMODeregistrationRequestMessage(), src='UE', dst='AMF')
        fgmm_deregistration_accept_ue = self.create_message(
            FGMMMODeregistrationAcceptMessage(), src='AMF', dst='UE')
        self.connect(src=fgmm_deregistration_request_ue,
                     dst=fgmm_deregistration_accept_ue,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.OPTIONAL)

        # AMF initiated
        # pylint: disable=undefined-variable
        fgmm_deregistration_request_amf = self.create_message(
            FGMMMTDeregistrationRequestMessage(), src='AMF', dst='UE')
        fgmm_deregistration_accept_amf = self.create_message(
            FGMMMTDeregistrationAcceptMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_deregistration_request_amf,
                     dst=fgmm_deregistration_accept_amf,
                     tags=EdgeTag.CONTROL_FLOW)

        ############################################################################################
        ###########               5.6 5GMM Connection Management Procedures             ############
        ############################################################################################

        ###
        # 5.6.1 Service Request Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_service_request = self.create_message(
            FGMMServiceRequestMessage(), src='UE', dst='AMF')
        fgmm_service_accept = self.create_message(
            FGMMServiceAcceptMessage(), src='AMF', dst='UE')
        fgmm_service_reject = self.create_message(
            FGMMServiceRejectMessage(), src='AMF', dst='UE')
        fgmm_control_plane_service_request = self.create_message(
            FGMMControlPlaneServiceRequestMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_service_request,
                     dst=fgmm_service_accept,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_service_request,
                     dst=fgmm_service_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_control_plane_service_request,
                     dst=fgmm_service_accept,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_control_plane_service_request,
                     dst=fgmm_service_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 5.6.3 Notification Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_notification = self.create_message(
            FGMMNotificationMessage(), src='AMF', dst='UE')
        fgmm_notification_response = self.create_message(
            FGMMNotificationResponseMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_notification,
                     dst=fgmm_notification_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_notification,
                     dst=fgmm_service_request,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_notification,
                     dst=fgmm_control_plane_service_request,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_notification,
                     dst=fgmm_registration_request,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.OPTIONAL)

        ############################################################################################
        ###################               5.4 5GMM Common Procedures             ###################
        ############################################################################################

        ###
        # 5.4.2 Security Mode Control Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_security_mode_command = self.create_message(
            FGMMSecurityModeCommandMessage(), src='AMF', dst='UE')
        fgmm_security_mode_complete = self.create_message(
            FGMMSecurityModeCompleteMessage(), src='UE', dst='AMF')
        fgmm_security_mode_reject = self.create_message(
            FGMMSecurityModeRejectMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_security_mode_command,
                     dst=fgmm_security_mode_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_security_mode_command,
                     dst=fgmm_security_mode_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_security_mode_command)
        self.connect(src=fgmm_security_mode_complete,
                     dst=fgmm_subprocedures)
        self.connect(src=fgmm_security_mode_reject,
                     dst=fgmm_subprocedures)

        ###
        # 5.4.3 Identification Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_identity_request = self.create_message(
            FGMMIdentityRequestMessage(), src='AMF', dst='UE')
        fgmm_identity_response = self.create_message(
            FGMMIdentityResponseMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_identity_request,
                     dst=fgmm_identity_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_identity_request)
        self.connect(src=fgmm_identity_response,
                     dst=fgmm_subprocedures)

        ###
        # 5.4.4 Generic UE Configuration Update Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_configuration_update_command = self.create_message(
            FGMMConfigurationUpdateCommandMessage(), src='AMF', dst='UE')
        fgmm_configuration_update_complete = self.create_message(
            FGMMConfigurationUpdateCompleteMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_configuration_update_command,
                     dst=fgmm_configuration_update_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)

        ###
        # 5.4.5 NAS Transport Procedure(s)
        ###

        # pylint: disable=undefined-variable
        fgmm_ul_nas_transport = self.create_message(
            FGMMULNASTransportMessage(), src='UE', dst='AMF')

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_ul_nas_transport)
        self.connect(src=fgmm_ul_nas_transport,
                     dst=fgmm_subprocedures)

        # pylint: disable=undefined-variable
        fgmm_dl_nas_transport = self.create_message(
            FGMMDLNASTransportMessage(), src='AMF', dst='UE')

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_dl_nas_transport)
        self.connect(src=fgmm_dl_nas_transport,
                     dst=fgmm_subprocedures)

        ###
        # 5.4.6 5GMM Status Procedure
        ###

        # AMF
        # pylint: disable=undefined-variable
        fgmm_status_amf = self.create_message(
            FGMMStatusMessage(), src='AMF', dst='UE')

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_status_amf)
        self.connect(src=fgmm_status_amf,
                     dst=fgmm_subprocedures)

        # UE
        # pylint: disable=undefined-variable
        fgmm_status_ue = self.create_message(
            FGMMStatusMessage(), src='UE', dst='AMF')

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_status_ue)
        self.connect(src=fgmm_status_ue,
                     dst=fgmm_subprocedures)

        ###
        # 5.4.7 Network Slice-Specific Authentication and Authorization Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_network_slice_spec_auth_command = self.create_message(
            FGMMNetworkSliceSpecAuthCommandMessage(), src='AMF', dst='UE')
        fgmm_network_slice_spec_auth_complete = self.create_message(
            FGMMNetworkSliceSpecAuthCompleteMessage(), src='UE', dst='AMF')
        fgmm_network_slice_spec_auth_result = self.create_message(
            FGMMNetworkSliceSpecAuthResultMessage(), src='AMF', dst='UE')
        self.connect(src=fgmm_network_slice_spec_auth_command,
                     dst=fgmm_network_slice_spec_auth_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_network_slice_spec_auth_complete,
                     dst=fgmm_network_slice_spec_auth_command,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_network_slice_spec_auth_complete,
                     dst=fgmm_network_slice_spec_auth_result,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_network_slice_spec_auth_command)
        self.connect(src=fgmm_network_slice_spec_auth_result,
                     dst=fgmm_subprocedures)

        ###
        # 5.4.1 Primary Authentication and Key Agreement Procedure
        ###

        # pylint: disable=undefined-variable
        fgmm_authentication_request = self.create_message(
            FGMMAuthenticationRequestMessage(), src='AMF', dst='UE')
        fgmm_authentication_response = self.create_message(
            FGMMAuthenticationResponseMessage(), src='UE', dst='AMF')
        fgmm_authentication_reject = self.create_message(
            FGMMAuthenticationRejectMessage(), src='AMF', dst='UE')
        fgmm_authentication_result = self.create_message(
            FGMMAuthenticationResultMessage(), src='AMF', dst='UE')
        fgmm_authentication_failure = self.create_message(
            FGMMAuthenticationFailureMessage(), src='UE', dst='AMF')
        self.connect(src=fgmm_authentication_request,
                     dst=fgmm_authentication_failure,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_authentication_request,
                     dst=fgmm_authentication_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_authentication_response,
                     dst=fgmm_authentication_request,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)

        self.connect(src=fgmm_authentication_response,
                     dst=fgmm_authentication_result,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_authentication_response,
                     dst=fgmm_authentication_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_authentication_request)
        self.connect(src=fgmm_authentication_failure,
                     dst=fgmm_subprocedures)
        self.connect(src=fgmm_authentication_response,
                     dst=fgmm_subprocedures)
        self.connect(src=fgmm_authentication_result,
                     dst=fgmm_subprocedures)
        self.connect(src=fgmm_authentication_reject,
                     dst=fgmm_subprocedures)

        ############################################################################################
        ##########################               Capabilities             ##########################
        ############################################################################################

        self.capabilities.append('Base')
        cap_add_base = self.create_capability(
            self.capabilities[0], CapabilityAction.ADD)
        cap_req_base = self.create_capability(
            self.capabilities[0], CapabilityAction.REQUIRE)

        self.capabilities.append('Registered')
        cap_add_registered = self.create_capability(
            self.capabilities[1], CapabilityAction.ADD)
        cap_req_registered = self.create_capability(
            self.capabilities[1], CapabilityAction.REQUIRE)
        self.connect(cap_req_base, cap_req_registered)
        self.connect(cap_req_registered, cap_req_base)
        cap_del_registered = self.create_capability(
            self.capabilities[1], CapabilityAction.REMOVE)
        self.connect(cap_del_registered, cap_req_base)

        ############################################################################################
        #####################               Procedure Dependencies             #####################
        ############################################################################################

        self.connect(src=cap_add_base)
        self.connect(src=cap_add_base, dst=cap_req_base)

        ###
        # Base procedures
        ###
        # the UE's initial registration request must be the first procedure
        self.connect(src=cap_req_base, dst=fgmm_registration_request)
        self.connect(src=fgmm_registration_reject, dst=cap_req_base)
        # common procedures can be initiated inside a registration request
        self.connect(src=fgmm_registration_request,
                     dst=fgmm_subprocedures,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_registration_accept,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_registration_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgmm_registration_accept,
                     dst=cap_add_registered)
        self.connect(src=fgmm_registration_complete,
                     dst=cap_add_registered)
        self.connect(src=cap_add_registered,
                     dst=cap_req_registered)

        self.connect(src=cap_req_base, dst=fgmm_service_request)
        self.connect(src=cap_req_base, dst=fgmm_control_plane_service_request)
        self.connect(src=fgmm_service_reject, dst=cap_req_base)
        # common procedures can be initiated inside a service request
        self.connect(src=fgmm_service_request,
                     dst=fgmm_subprocedures,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_control_plane_service_request,
                     dst=fgmm_subprocedures,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_subprocedures,
                     dst=fgmm_service_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        self.connect(src=cap_req_base, dst=fgmm_notification)
        self.connect(src=fgmm_notification_response, dst=cap_req_base)

        self.connect(src=cap_req_base, dst=fgmm_subprocedures)
        self.connect(src=fgmm_subprocedures, dst=cap_req_base)

        ###
        # Procedures dependant on the registration capability
        ###
        self.connect(src=cap_req_registered, dst=fgmm_deregistration_request_ue,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_deregistration_request_ue, dst=cap_del_registered)
        self.connect(src=fgmm_deregistration_accept_ue, dst=cap_del_registered)

        self.connect(src=cap_req_registered, dst=fgmm_deregistration_request_amf,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_deregistration_accept_amf, dst=cap_del_registered)

        self.connect(src=cap_req_registered, dst=fgmm_configuration_update_command,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgmm_configuration_update_command, dst=cap_req_registered)
        self.connect(src=fgmm_configuration_update_complete, dst=cap_req_registered)


@register(Protocol, 'NAS-SM', append_name=False)
class NASSMProtocol(CapabilityProtocol):
    """Represents the NAS-SM (Non-Access Stratum) protocol (Session Management subset) used in 5G networks.

    This class provides methods and attributes specific to the NAS-SM protocol, facilitating
    the management of various procedures such as PDU session management, UE context management,
    UE mobility management, and more.
    """

    def __init__(self):
        """Initializes the `NASSMProtocol` instance with all the nodes and edges required by the 
        NAS-SM protocol.
        """

        super().__init__('NAS-SM')
        self._init()

    # pylint: disable=too-many-locals
    def _init(self):
        """Initialize the graph with all the nodes and edges required."""

        ############################################################################################
        ################               6.4 UE-Requested 5GSM Procedures             ################
        ############################################################################################

        ###
        # 6.4.1 UE-Requested PDU Session Establishment Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_pdu_session_establishment_request = self.create_message(
            FGSMPDUSessionEstabRequestMessage(), src='UE', dst='SMF')
        fgsm_pdu_session_establishment_accept = self.create_message(
            FGSMPDUSessionEstabAcceptMessage(), src='SMF', dst='UE')
        fgsm_pdu_session_establishment_reject = self.create_message(
            FGSMPDUSessionEstabRejectMessage(), src='SMF', dst='UE')
        self.connect(src=fgsm_pdu_session_establishment_request,
                     dst=fgsm_pdu_session_establishment_accept,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_establishment_request,
                     dst=fgsm_pdu_session_establishment_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 6.4.2 UE-Requested PDU Session Modification Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_pdu_session_modification_request = self.create_message(
            FGSMPDUSessionModifRequestMessage(), src='UE', dst='SMF')
        fgsm_pdu_session_modification_reject = self.create_message(
            FGSMPDUSessionModifRejectMessage(), src='SMF', dst='UE')
        self.connect(src=fgsm_pdu_session_modification_request,
                     dst=fgsm_pdu_session_modification_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 6.4.3 UE-Requested PDU Session Release Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_pdu_session_release_request = self.create_message(
            FGSMPDUSessionReleaseRequestMessage(), src='UE', dst='SMF')
        fgsm_pdu_session_release_reject = self.create_message(
            FGSMPDUSessionReleaseRejectMessage(), src='SMF', dst='UE')
        self.connect(src=fgsm_pdu_session_release_request,
                     dst=fgsm_pdu_session_release_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ############################################################################################
        ####################               6.5 5GSM Status Procedure             ###################
        ############################################################################################

        # SMF
        # pylint: disable=undefined-variable
        fgsm_status_smf = self.create_message(
            FGSMStatusMessage(), src='SMF', dst='UE')

        # UE
        # pylint: disable=undefined-variable
        fgsm_status_ue = self.create_message(
            FGSMStatusMessage(), src='UE', dst='SMF')

        ############################################################################################
        ###############               6.6 5GSM Miscellaneous Procedures             ################
        ############################################################################################

        ###
        # 6.6.2 Remote UE Report Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_remote_ue_report = self.create_message(
            FGSMRemoteUEReportMessage(), src='UE', dst='SMF')
        fgsm_remote_ue_report_response = self.create_message(
            FGSMRemoteUEReportResponseMessage(), src='SMF', dst='UE')
        self.connect(src=fgsm_remote_ue_report,
                     dst=fgsm_remote_ue_report_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ############################################################################################
        ##############               6.3 Network Requested 5GSM Procedures             #############
        ############################################################################################

        fgsm_sub_procedures = self.create_dummy()

        ###
        # 6.3.2 Network-Requested PDU Session Modification Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_pdu_session_modification_command = self.create_message(
            FGSMPDUSessionModifCommandMessage(), src='SMF', dst='UE')
        fgsm_pdu_session_modification_complete = self.create_message(
            FGSMPDUSessionModifCompleteMessage(), src='UE', dst='SMF')
        fgsm_pdu_session_modification_command_reject = self.create_message(
            FGSMPDUSessionModifCommandRejectMessage(), src='UE', dst='SMF')
        self.connect(src=fgsm_pdu_session_modification_command,
                     dst=fgsm_pdu_session_modification_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_modification_command,
                     dst=fgsm_pdu_session_modification_command_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        ###
        # 6.3.3 Network-Requested PDU Session Release Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_pdu_session_release_command = self.create_message(
            FGSMPDUSessionReleaseCommandMessage(), src='SMF', dst='UE')
        fgsm_pdu_session_release_complete = self.create_message(
            FGSMPDUSessionReleaseCompleteMessage(), src='UE', dst='SMF')
        self.connect(src=fgsm_pdu_session_release_command,
                     dst=fgsm_pdu_session_release_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)

        ###
        # 6.3.1 PDU Session Authentication and Authorization Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_pdu_session_auth_command = self.create_message(
            FGSMPDUSessionAuthentCommandMessage(), src='SMF', dst='UE')
        fgsm_pdu_session_auth_complete = self.create_message(
            FGSMPDUSessionAuthentCompleteMessage(), src='UE', dst='SMF')
        fgsm_pdu_session_auth_result = self.create_message(
            FGSMPDUSessionAuthentResultMessage(), src='SMF', dst='UE')
        self.connect(src=fgsm_pdu_session_auth_command,
                     dst=fgsm_pdu_session_auth_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_auth_complete,
                     dst=fgsm_pdu_session_auth_command,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)
        # self.connect(src=fgsm_pdu_session_auth_complete,
        #             dst=fgsm_pdu_session_establishment_accept,
        #             tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)
        # self.connect(src=fgsm_pdu_session_auth_complete,
        #             dst=fgsm_pdu_session_establishment_reject,
        #             tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgsm_pdu_session_auth_complete,
                     dst=fgsm_pdu_session_auth_result,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)
        # self.connect(src=fgsm_pdu_session_auth_complete,
        #             dst=fgsm_pdu_session_release_command,
        #             tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgsm_pdu_session_auth_complete,
                     dst=fgsm_remote_ue_report_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)

        self.connect(src=fgsm_sub_procedures,
                     dst=fgsm_pdu_session_auth_command)
        self.connect(src=fgsm_pdu_session_auth_complete,
                     dst=fgsm_sub_procedures)
        self.connect(src=fgsm_pdu_session_auth_result,
                     dst=fgsm_sub_procedures)

        ###
        # 6.3.1A Service-Level Session Authentication and Authorization Procedure
        ###

        # pylint: disable=undefined-variable
        fgsm_service_level_auth_command = self.create_message(
            FGSMServiceLevelAuthCommandMessage(), src='SMF', dst='UE')
        fgsm_service_level_auth_complete = self.create_message(
            FGSMServiceLevelAuthCompleteMessage(), src='UE', dst='SMF')
        self.connect(src=fgsm_service_level_auth_command,
                     dst=fgsm_service_level_auth_complete,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_service_level_auth_complete,
                     dst=fgsm_service_level_auth_command,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)

        self.connect(src=fgsm_sub_procedures,
                     dst=fgsm_service_level_auth_command)
        self.connect(src=fgsm_service_level_auth_complete,
                     dst=fgsm_sub_procedures)
        self.connect(src=fgsm_pdu_session_auth_result,
                     dst=fgsm_sub_procedures)

        ############################################################################################
        ##########################               Capabilities             ##########################
        ############################################################################################

        self.capabilities.append('PDU Session')
        cap_add_pdu_sess_active = self.create_capability(
            self.capabilities[0], CapabilityAction.ADD)
        cap_req_pdu_sess_active = self.create_capability(
            self.capabilities[0], CapabilityAction.REQUIRE)
        cap_del_pdu_sess_active = self.create_capability(
            self.capabilities[0], CapabilityAction.REMOVE)

        ############################################################################################
        #####################               Procedure Dependencies             #####################
        ############################################################################################

        fgsm_starting_point = self.create_dummy()

        self.connect(src=fgsm_starting_point)
        self.connect(src=fgsm_starting_point, dst=fgsm_pdu_session_establishment_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        # subprocedures can be initiated inside a session establishment request
        self.connect(src=fgsm_pdu_session_establishment_request,
                     dst=fgsm_sub_procedures,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_sub_procedures,
                     dst=fgsm_pdu_session_establishment_accept,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_sub_procedures,
                     dst=fgsm_pdu_session_establishment_reject,
                     tags=EdgeTag.ERROR_HANDLING | EdgeTag.OPTIONAL)
        self.connect(src=fgsm_pdu_session_establishment_reject, dst=fgsm_starting_point)
        self.connect(src=fgsm_pdu_session_establishment_accept,
                     dst=cap_add_pdu_sess_active)
        self.connect(src=cap_add_pdu_sess_active,
                     dst=cap_req_pdu_sess_active)

        ###
        # Procedures dependant on the PDU session capability
        ###
        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_pdu_session_modification_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_modification_reject, dst=cap_req_pdu_sess_active)
        self.connect(src=fgsm_pdu_session_modification_reject, dst=cap_del_pdu_sess_active)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_pdu_session_modification_command,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_modification_complete, dst=cap_req_pdu_sess_active)
        self.connect(src=fgsm_pdu_session_modification_command_reject, dst=cap_req_pdu_sess_active)
        self.connect(src=fgsm_pdu_session_modification_command_reject, dst=cap_del_pdu_sess_active)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_remote_ue_report,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_remote_ue_report_response, dst=cap_req_pdu_sess_active)
        # subprocedures can be initiated inside an ue report request
        self.connect(src=fgsm_remote_ue_report,
                     dst=fgsm_sub_procedures,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_sub_procedures,
                     dst=fgsm_remote_ue_report_response,
                     tags=EdgeTag.CONTROL_FLOW | EdgeTag.ERROR_HANDLING | EdgeTag.DATA_DEPENDENCY | EdgeTag.OPTIONAL)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_status_smf,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_status_smf, dst=cap_req_pdu_sess_active)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_status_ue,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_status_ue, dst=cap_req_pdu_sess_active)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_pdu_session_release_request,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_release_reject, dst=cap_req_pdu_sess_active)
        self.connect(src=fgsm_pdu_session_release_request, dst=cap_del_pdu_sess_active)
        self.connect(src=fgsm_pdu_session_release_request, dst=fgsm_pdu_session_release_command)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_pdu_session_release_command,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_pdu_session_release_complete, dst=cap_del_pdu_sess_active)

        self.connect(src=cap_req_pdu_sess_active, dst=fgsm_sub_procedures,
                     tags=EdgeTag.OPTIONAL | EdgeTag.DATA_DEPENDENCY)
        self.connect(src=fgsm_sub_procedures, dst=cap_req_pdu_sess_active)


__all__ = ['NASMMProtocol', 'NASSMProtocol']
