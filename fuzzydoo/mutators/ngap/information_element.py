from ...mutator import mutates
from ...proto.ngap.messages import InformationElement
from ...proto.ngap.aper import AperEntity
from .aper import AperPreambleBaseMutator, AperLengthBaseMutator


@mutates(InformationElement)
class IEAperPreambleRandomMutator(AperPreambleBaseMutator[InformationElement]):
    """Mutator for `InformationElement` objects that generate random values for the APER preamble."""

    FIELD_NAME = 'ie_preamble'


@mutates(InformationElement)
class IEAperLengthRandomMutator(AperLengthBaseMutator[InformationElement]):
    """Mutator for `InformationElement` objects that generate random values for the APER length 
    without requiring some fragmentation."""

    FIELD_NAME = 'ie_content_length'

    GENERATION_RANGE = (0, AperEntity.DETERMINANT_SIZES[0])


@mutates(InformationElement)
class IEAperFragmentedLengthRandomMutator(AperLengthBaseMutator[InformationElement]):
    """Mutator for `InformationElement` objects that generate random values for the APER length 
    such that it requires fragmentation."""

    FIELD_NAME = 'ie_content_length'

    GENERATION_RANGE = (AperEntity.DETERMINANT_SIZES[0], AperEntity.DETERMINANT_SIZES[-1])


__all__ = [
    'IEAperPreambleRandomMutator',
    'IEAperLengthRandomMutator',
    'IEAperFragmentedLengthRandomMutator'
]
