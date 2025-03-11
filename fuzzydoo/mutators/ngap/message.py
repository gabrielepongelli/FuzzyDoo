from ...mutator import mutates
from ...proto.ngap.messages import NGAPMessage
from ...proto.ngap.aper import AperEntity
from .aper import AperPreambleBaseMutator, AperLengthBaseMutator


@mutates(NGAPMessage)
class MessageAperPreambleRandomMutator(AperPreambleBaseMutator):
    """Mutator for `NGAPMessage` objects that generate random values for the APER preamble."""

    ATTRIBUTE_NAME = 'message_type_preamble'


@mutates(NGAPMessage)
class MessageAperContentLengthRandomMutator(AperLengthBaseMutator):
    """Mutator for `NGAPMessage` objects that generate random values for the APER length of the 
    content without requiring some fragmentation."""

    ATTRIBUTE_NAME = 'message_value_length'

    GENERATION_RANGE = (0, AperEntity.DETERMINANT_SIZES[0])


@mutates(NGAPMessage)
class MessageAperFragmentedContentLengthRandomMutator(AperLengthBaseMutator):
    """Mutator for `NGAPMessage` objects that generate random values for the APER length of the 
    content such that it requires fragmentation."""

    ATTRIBUTE_NAME = 'message_value_length'

    GENERATION_RANGE = (AperEntity.DETERMINANT_SIZES[0], AperEntity.DETERMINANT_SIZES[-1])


@mutates(NGAPMessage)
class MessageAperIEsNumberRandomMutator(AperLengthBaseMutator):
    """Mutator for `NGAPMessage` objects that generate random values for the APER field 
    representing the number of IEs in the message without requiring some fragmentation."""

    ATTRIBUTE_NAME = 'n_ies'

    GENERATION_RANGE = (0, AperEntity.DETERMINANT_SIZES[0])


@mutates(NGAPMessage)
class MessageAperFragmentedIEsNumberRandomMutator(AperLengthBaseMutator):
    """Mutator for `NGAPMessage` objects that generate random values for the APER field 
    representing the number of IEs in the message such that it requires fragmentation."""

    ATTRIBUTE_NAME = 'n_ies'

    GENERATION_RANGE = (AperEntity.DETERMINANT_SIZES[0], AperEntity.DETERMINANT_SIZES[-1])


__all__ = [
    'MessageAperPreambleRandomMutator',
    'MessageAperContentLengthRandomMutator',
    'MessageAperFragmentedContentLengthRandomMutator',
    "MessageAperIEsNumberRandomMutator",
    "MessageAperFragmentedIEsNumberRandomMutator"
]
