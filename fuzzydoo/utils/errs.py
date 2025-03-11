############################################################################################
###########################               Base Errors             ##########################
############################################################################################


class FuzzyDooError(Exception):
    """Generic error for the FuzzyDoo package."""


############################################################################################
##########################               Agent Errors             ##########################
############################################################################################


class AgentError(FuzzyDooError):
    """Generic error for the `Agent` interface."""


class UnknownAgentError(AgentError):
    """Exception raised when an unknown agent type is encountered."""


############################################################################################
#########################               Fuzzable Errors             ########################
############################################################################################


class FuzzableError(FuzzyDooError):
    """Generic error for the `Fuzzable` interface."""


class QualifiedNameFormatError(FuzzableError):
    """Exception raised when an invalid qualified name is provided."""


class ContentNotFoundError(FuzzableError):
    """Exception raised when some content specified is not found."""


############################################################################################
#########################               Protocol Errors             ########################
############################################################################################


class ProtocolError(FuzzyDooError):
    """Generic error for the `Protocol` class."""


class InvalidPathError(ProtocolError):
    """Error raised when the provided path is invalid."""


class UnknownProtocolError(ProtocolError):
    """Exception raised when an unknown protocol type is encountered."""


############################################################################################
#########################               Message Errors             #########################
############################################################################################


class MessageError(FuzzyDooError):
    """Generic error for the `Message` interface."""


class UnknownMessageError(MessageError):
    """Exception raised when an unknown message type is encountered."""


class MessageParsingError(MessageError):
    """Exception raised when an error occurs while parsing a message."""


############################################################################################
########################               Publisher Errors             ########################
############################################################################################


class PublisherError(FuzzyDooError):
    """Generic error for the `Publisher` interface."""


class PublisherOperationError(PublisherError):
    """Exception raised when a publisher encounters an error during send/receive operations."""


class UnknownPublisherError(PublisherError):
    """Exception raised when an unknown publisher type is encountered."""


############################################################################################
##########################               Engine Errors             #########################
############################################################################################


class FuzzingEngineError(FuzzyDooError):
    """Generic error for the `Engine` class."""


class SetupFailedError(FuzzingEngineError):
    """Exception raised when an error occurs during a run/epoch/test case setup."""


class TestCaseExecutionError(FuzzingEngineError):
    """Exception raised when an error occurs during test case execution."""


############################################################################################
#######################               Transformer Errors             #######################
############################################################################################


class TransformerError(FuzzyDooError):
    """Generic error for the `Transformer` interface."""


class TransformationError(TransformerError):
    """Error raised when a transformation operation fails."""


class EncodingError(TransformationError):
    """Error raised when an encoding operation fails."""


class DecodingError(TransformationError):
    """Error raised when a decoding operation fails."""


class UnknownTransformerError(TransformerError):
    """Exception raised when an unknown transformer type is encountered."""


__all__ = [
    'FuzzyDooError',
    'AgentError',
    'UnknownAgentError',
    'FuzzableError',
    'QualifiedNameFormatError',
    'ContentNotFoundError',
    'ProtocolError',
    'InvalidPathError',
    'UnknownProtocolError',
    'MessageError',
    'UnknownMessageError',
    'MessageParsingError',
    'PublisherError',
    'PublisherOperationError',
    'UnknownPublisherError',
    'FuzzingEngineError',
    'SetupFailedError',
    'TestCaseExecutionError',
    'TransformerError',
    'TransformationError',
    'EncodingError',
    'DecodingError',
    'UnknownTransformerError'
]
