from typing import Any, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.nas.types import BufferType


@mutates(BufferType)
class BufferMutator(Mutator):
    """Mutator for `BufferType` objects that generate random values."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume a size of 64 bytes, later when we get a reference of the particular
        # instance we are working on, we will modify this
        self._size: int | None = None
        self._extracted_values: set[bytes] | None = None

        # for cases in which there is a list of allowed values
        self._possible_values: list[bytes] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `OctStrMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                `'rand_state'`: The state of the random number generator.
                `'size'` (optional): The size of the string in bytes.
                `'extracted_values'` (optional): The set of already extracted values.
                `'possible_values'` (optional): The list of possible values if the range size is =< 256.
        """

        state = {'rand_state': self._rand.getstate()}

        if self._size is not None:
            state['size'] = self._size

        if self._extracted_values is not None:
            state['extracted_values'] = set(self._extracted_values)

        if self._possible_values is not None:
            state['possible_values'] = list(self._possible_values)

        return state

    def _mutate(self, data: BufferType | None, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        size = self._size
        extracted_values = self._extracted_values
        possible_values = self._possible_values
        set_state = size is None and possible_values is None

        if state is not None:
            rand.setstate(state['rand_state'])
            size = state.get('size', None)
            extracted_values = state.get('extracted_values', None)
            possible_values = state.get('possible_values', None)
        elif set_state:
            if data:
                if data.possible_values:
                    possible_values = data.possible_values
                else:
                    size = data.bit_length // 8
                    extracted_values = set()
            else:
                size = 64
                extracted_values = set()

            self._size = size
            self._extracted_values = extracted_values
            self._possible_values = possible_values

        if possible_values is not None:
            value = rand.choice(possible_values)
        else:
            while True:
                value = rand.randbytes(size)
                if value not in extracted_values:
                    break

        if update_state:
            if possible_values is not None:
                self._possible_values.remove(value)
                if len(self._possible_values) == 0:
                    raise MutatorCompleted()
            elif extracted_values is not None:
                self._extracted_values.add(value)
                if len(self._extracted_values) == 2**(size * 8):
                    raise MutatorCompleted()
        else:
            return Mutation(mutator=type(self),
                            mutator_state=self._export_state(),
                            field_name=data.name,
                            mutated_value=value)

    @override
    def next(self):
        self._mutate(None, True)

    @override
    def mutate(self, data: BufferType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


__all__ = ['BufferMutator']
