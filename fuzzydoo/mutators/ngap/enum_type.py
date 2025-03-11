from typing import Any, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import EnumType


@mutates(EnumType)
class EnumMutator(Mutator):
    """Mutator for `EnumType` objects."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._possible_values: list[str] | None = None
        self._last_extracted_value: str | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `EnumMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'possible_values'`: The list of possible values that haven't been used yet.
        """

        return {
            'rand_state': self._rand.getstate(),
            'possible_values': list(self._possible_values) if self._possible_values is not None else None
        }

    @override
    def next(self):
        self._possible_values.remove(self._last_extracted_value)
        if len(self._possible_values) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: EnumType, state: dict[str, Any] | None = None) -> Mutation:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            possible_values = state['possible_values']
            mutator_state = state
        elif self._possible_values is None:
            self._possible_values = possible_values = data.possible_values
            mutator_state = self._export_state()
        else:
            possible_values = self._possible_values
            mutator_state = self._export_state()

        self._last_extracted_value = rand.choice(possible_values)

        if state is None:
            self._rand = rand

        return Mutation(
            mutator=type(self),
            mutator_state=mutator_state,
            field_name=data.name,
            mutated_value=self._last_extracted_value
        )


__all__ = ['EnumMutator']
