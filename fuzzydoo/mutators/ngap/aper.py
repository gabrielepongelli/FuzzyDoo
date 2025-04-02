from typing import Any, Generic, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, FuzzableT


class AperPreambleBaseMutator(Mutator[FuzzableT, str], Generic[FuzzableT]):
    """Base mutator that generates random values for the APER preamble."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._size: int | None = None
        self._extracted_values: set[str] = set()
        self._last_extracted_value: str | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `AperPreambleBaseMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'size'`: The size of the preamble to modify.
                - `'extracted_values'`: The set of already extracted values.
        """

        return {
            'rand_state': self._rand.getstate(),
            'size': self._size,
            'extracted_values': set(self._extracted_values),
        }

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)
        if len(self._extracted_values) == 2**self._size:
            raise MutatorCompleted()

    @override
    def mutate(self, data: FuzzableT, state: dict[str, Any] | None = None) -> Mutation[str]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            size = state['size']
            extracted_values = state['extracted_values']
            mutator_state = state
        elif self._size is None:
            self._size = size = len(getattr(data, self.FIELD_NAME))
            if not size:
                # if there is no preamble
                raise MutatorNotApplicable()

            self._extracted_values.add(getattr(data, self.FIELD_NAME))
            extracted_values = self._extracted_values

            mutator_state = self._export_state()
        else:
            size = self._size
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            val = rand.randrange(0, 2**size)
            self._last_extracted_value = bin(val)[2:].rjust(size, '0')
            if self._last_extracted_value not in extracted_values:
                break

        if state is None:
            self._rand = rand

        return Mutation[str](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=getattr(data, self.FIELD_NAME),
            mutated_value=self._last_extracted_value
        )


class AperLengthBaseMutator(Mutator[FuzzableT, int], Generic[FuzzableT]):
    """Base mutator that generates random lengths for the APER encoding."""

    GENERATION_RANGE: tuple[int, int] = (0, 0)

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._extracted_values: set[int] = set()
        self._last_extracted_value: int | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `AperLengthBaseMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'extracted_values'`: The set of already extracted values.
        """

        return {
            'rand_state': self._rand.getstate(),
            'extracted_values': set(self._extracted_values),
        }

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)
        if len(self._extracted_values) == self.GENERATION_RANGE[1] - self.GENERATION_RANGE[0] + 1:
            raise MutatorCompleted()

    @override
    def mutate(self, data: FuzzableT, state: dict[str, Any] | None = None) -> Mutation[int]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            mutator_state = state
        elif not self._extracted_values:
            length = getattr(data, self.FIELD_NAME)
            if not length:
                # if there is no content length specified
                raise MutatorNotApplicable()

            self._extracted_values.add(length)
            extracted_values = self._extracted_values

            mutator_state = self._export_state()
        else:
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            self._last_extracted_value = rand.randrange(
                self.GENERATION_RANGE[0], self.GENERATION_RANGE[1])
            if self._last_extracted_value not in extracted_values:
                break

        if state is None:
            self._rand = rand

        return Mutation[int](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=getattr(data, self.FIELD_NAME),
            mutated_value=self._last_extracted_value
        )
