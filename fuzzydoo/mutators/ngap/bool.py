from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import BoolType


@mutates(BoolType)
class BoolMutator(Mutator):
    """Mutator for `BoolType` objects."""

    def next(self):
        raise MutatorCompleted()

    # pylint: disable=signature-differs
    def mutate(self, data: BoolType, _) -> Mutation:
        return Mutation(mutator=type(self), mutator_state={},
                        field_name=data.name,
                        mutated_value=not data.value)


__all__ = ['BoolMutator']
