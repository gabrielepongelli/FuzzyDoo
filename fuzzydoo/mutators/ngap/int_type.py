from typing import Any, ClassVar, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, mutates
from ...proto.ngap.types import IntType


@mutates(IntType)
class IntRandomMutator(Mutator[IntType, int]):
    """Mutator for `IntType` objects that generate random values in the integer boundaries."""

    FIELD_NAME = 'value'

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._range_limits: list[tuple[int, int]] = []
        self._extracted_values: list[set[int]] = []
        self._last_extracted_value: tuple[int, int] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `IntRandomMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'range_limits'`: The list of limits of the range values in which values should 
                        be generated.
                - `'extracted_values'`: The set of already extracted values for each range limits.
        """

        return {
            'rand_state': self._rand.getstate(),
            'range_limits': list(self._range_limits),
            'extracted_values': [set(i) for i in self._extracted_values],
        }

    @override
    def next(self):
        range_idx, val = self._last_extracted_value
        self._extracted_values[range_idx].add(val)

        # remove a range if all its values were extracted
        lb, ub = self._range_limits[range_idx]
        if len(self._extracted_values[range_idx]) == ub - lb:
            del self._range_limits[range_idx]
            del self._extracted_values[range_idx]

        if len(self._range_limits) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: IntType, state: dict[str, Any] | None = None) -> Mutation[int]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            range_limits = state['range_limits']
            extracted_values = state['extracted_values']
            mutator_state = state
        elif not self._range_limits:
            if not data.possible_values:
                # it means that every value is expected
                raise MutatorNotApplicable()

            self._extracted_values = extracted_values = set(data.possible_values)

            self._range_limits = range_limits = data.possible_ranges
            if not range_limits:
                # it means that every value is possible
                raise MutatorNotApplicable()

            n_values = sum(ub - lb for lb, ub in range_limits)
            if len(extracted_values) == n_values:
                # even if there are some specific possible values, these comprehend all the
                # possible values in the range
                raise MutatorNotApplicable()

            mutator_state = self._export_state()
        else:
            range_limits = self._range_limits
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            range_idx = rand.randrange(0, len(self._range_limits))
            lb, ub = self._range_limits[range_idx]
            val = rand.randrange(lb, ub)
            if val not in extracted_values[range_idx]:
                self._last_extracted_value = (range_idx, val)
                break

        if state is None:
            self._rand = rand

        return Mutation[int](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=val
        )


@mutates(IntType)
class IntEdgeMutator(Mutator[IntType, int]):
    """Mutator for `IntType` objects that generate random values that are at around the edges of the
    allowed range.
    """

    FIELD_NAME = 'value'

    DELTA: ClassVar[int] = 3

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._possible_values: list[int] = []
        self._last_extracted_value: int | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `IntEdgeMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'possible_values'`: The possible values that haven't been already used.
        """

        return {
            'rand_state': self._rand.getstate(),
            'possible_values': list(self._possible_values)
        }

    @override
    def next(self):
        self._possible_values.remove(self._last_extracted_value)
        if len(self._possible_values) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: IntType, state: dict[str, Any] | None = None) -> Mutation[int]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            possible_values = state['possible_values']
            mutator_state = state
        elif not self._possible_values:
            ranges = list(filter(lambda r: r[1] - r[0] > self.DELTA * 4, data.possible_ranges))
            if not ranges:
                raise MutatorNotApplicable()

            all_values = set()
            for lb, ub in ranges:
                all_values.update(
                    range(lb - self.DELTA, lb + self.DELTA + 1),
                    range(ub - self.DELTA, ub + self.DELTA + 1)
                )

            self._possible_values = possible_values = list(all_values)

            mutator_state = self._export_state()
        else:
            possible_values = self._possible_values
            mutator_state = self._export_state()

        self._last_extracted_value = rand.choice(possible_values)

        if state is None:
            self._rand = rand

        return Mutation[int](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=self._last_extracted_value
        )


__all__ = ['IntRandomMutator', 'IntEdgeMutator']
