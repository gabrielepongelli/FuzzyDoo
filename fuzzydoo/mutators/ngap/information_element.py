from ...mutator import mutates
from ...proto.ngap.messages import InformationElement
from ...proto.ngap.aper import AperEntity
from .aper import AperPreambleBaseMutator, AperLengthBaseMutator


@mutates(InformationElement)
class IEAperPreambleRandomMutator(AperPreambleBaseMutator):
    """Mutator for `InformationElement` objects that generate random values for the APER preamble."""

    ATTRIBUTE_NAME = 'ie_preamble'


@mutates(InformationElement)
class IEAperLengthRandomMutator(AperLengthBaseMutator):
    """Mutator for `InformationElement` objects that generate random values for the APER length 
    without requiring some fragmentation."""

    ATTRIBUTE_NAME = 'ie_content_length'

    GENERATION_RANGE = (0, AperEntity.DETERMINANT_SIZES[0])


@mutates(InformationElement)
class IEAperFragmentedLengthRandomMutator(AperLengthBaseMutator):
    """Mutator for `InformationElement` objects that generate random values for the APER length 
    such that it requires fragmentation."""

    ATTRIBUTE_NAME = 'ie_content_length'

    GENERATION_RANGE = (AperEntity.DETERMINANT_SIZES[0], AperEntity.DETERMINANT_SIZES[-1])


__all__ = [
    'IEAperPreambleRandomMutator',
    'IEAperLengthRandomMutator',
    'IEAperFragmentedLengthRandomMutator'
]
