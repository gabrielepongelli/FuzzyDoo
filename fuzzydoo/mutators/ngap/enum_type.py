from typing import Any
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import EnumType


@mutates(EnumType)
class EnumMutator(Mutator):
    """Mutator for `EnumType` objects."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)
        self._possible_values: list[int] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `EnumMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'rand_state': The state of the random number generator.
                'possible_values': The list of possible values that haven't been used yet.
        """

        return {
            'rand_state': self._rand.getstate(),
            'possible_values': list(self._possible_values) if self._possible_values is not None else None
        }

    def _mutate(self, data: EnumType, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        possible_values = self._possible_values
        set_state = possible_values is None

        if state is not None:
            rand.setstate(state['rand_state'])
            possible_values = state['possible_values']
        elif set_state:
            self._possible_values = data.possible_values

        value = rand.choice(possible_values)

        if update_state:
            self._possible_values.remove(value)
            if len(self._possible_values) == 0:
                raise MutatorCompleted()
        else:
            return Mutation(mutator=type(self),
                            mutator_state=self._export_state(),
                            field_name=data.name,
                            mutated_value=value)

    def next(self):
        self._mutate(True, None)

    def mutate(self, data: EnumType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(False, data, state)


__all__ = ['EnumMutator']
