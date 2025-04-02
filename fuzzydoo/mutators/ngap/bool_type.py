from typing import override

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import BoolType


@mutates(BoolType)
class BoolMutator(Mutator[BoolType, bool]):
    """Mutator for `BoolType` objects."""

    FIELD_NAME = 'value'

    @override
    def next(self):
        raise MutatorCompleted()

    # pylint: disable=signature-differs
    @override
    def mutate(self, data: BoolType, _) -> Mutation[bool]:
        return Mutation[bool](
            mutator=type(self),
            mutator_state=None,
            qname=data.name,
            field_name=self.FIELD_NAME,
            mutated_value=not data.value
        )


__all__ = ['BoolMutator']
