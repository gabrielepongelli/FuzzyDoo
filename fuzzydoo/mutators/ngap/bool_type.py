from typing import override

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import BoolType


@mutates(BoolType)
class BoolMutator(Mutator):
    """Mutator for `BoolType` objects."""

    @override
    def next(self):
        raise MutatorCompleted()

    # pylint: disable=signature-differs
    @override
    def mutate(self, data: BoolType, _) -> Mutation:
        return Mutation(mutator=type(self), mutator_state={},
                        field_name=data.name,
                        mutated_value=not data.value)


__all__ = ['BoolMutator']
