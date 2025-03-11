from typing import Any, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, mutates
from ...proto.nas.types import IntType, UintType, IntLEType, UintLEType


signed_integer_limits = lambda n_bits: (-(2 ** (n_bits - 1)), 2 ** (n_bits - 1))


@mutates(IntType, UintType, IntLEType, UintLEType)
class IntRandomMutator(Mutator):
    """Mutator for generic integer objects that generate random values in the integer boundaries."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._range_limits: tuple[int, int] | None = None
        self._extracted_values: set[int] = set()
        self._last_extracted_value: int | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'range_limits'`: The limits of the range values in which values should be 
                        generated.
                - `'extracted_values'`: The set of already extracted values.
        """

        return {
            'rand_state': self._rand.getstate(),
            'range_limits': self._range_limits,
            'extracted_values': set(self._extracted_values),
        }

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)
        if len(self._extracted_values) == self._range_limits[1] - self._range_limits[0]:
            raise MutatorCompleted()

    @override
    def mutate(self, data: IntType | UintType | IntLEType | UintLEType, state: dict[str, Any] | None = None) -> Mutation:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            range_limits = state['range_limits']
            extracted_values = state['extracted_values']
            mutator_state = state
        elif self._range_limits is None:
            if not data.possible_values:
                # it means that every value is expected
                raise MutatorNotApplicable()

            self._extracted_values = extracted_values = set(data.possible_values)

            if isinstance(data, (UintType, UintLEType)):
                self._range_limits = range_limits = (0, 2**data.bit_length)
            else:
                self._range_limits = range_limits = signed_integer_limits(data.bit_length)

            if len(extracted_values) == range_limits[1] - range_limits[0]:
                # even if there are some specific possible values, these comprehend all the
                # possible values in the range
                raise MutatorNotApplicable()

            mutator_state = self._export_state()
        else:
            range_limits = self._range_limits
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            self._last_extracted_value = rand.randrange(range_limits[0], range_limits[1])
            if self._last_extracted_value not in extracted_values:
                break

        if state is None:
            self._rand = rand

        return Mutation(
            mutator=type(self),
            mutator_state=mutator_state,
            field_name=data.name,
            mutated_value=self._last_extracted_value
        )


@mutates(IntType, UintType, IntLEType, UintLEType)
class IntEdgeMutator(Mutator):
    """Mutator for generic integer objects that generate random values that are around the edges of 
    the allowed range.
    """

    _DELTA = 3

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._possible_values: list[int] = []
        self._last_extracted_value: int | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'possible_values'`: The list of possible values that haven't been already used.
        """

        return {
            'rand_state': self._rand.getstate(),
            'possible_values': list(self._possible_values)
        }

    def _generate_values_from_limit(self, limit: int) -> list[int]:
        """Generate edge values given a limit.

        Args:
            limit: The limit to generate around.

        Returns:
            list[int]: A list of values in [limit-DELTA, limit+DELTA].
        """

        return list(range(limit - self._DELTA, limit + self._DELTA + 1))

    @override
    def next(self):
        self._possible_values.remove(self._last_extracted_value)
        if len(self._possible_values) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: IntType | UintType | IntLEType | UintLEType, state: dict[str, Any] | None = None) -> Mutation:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            possible_values = state['possible_values']
            mutator_state = state
        elif not self._possible_values:
            if isinstance(data, (UintType, UintLEType)):
                limits = (0, 2**data.bit_length)
            else:
                limits = signed_integer_limits(data.bit_length)

            if limits[1] - limits[0] <= self._DELTA * 4:
                # it doesn't make sense to apply
                raise MutatorNotApplicable()

            possible_values = self._generate_values_from_limit(limits[1])
            if not isinstance(data, (UintType, UintLEType)):
                possible_values += self._generate_values_from_limit(limits[0])
            self._possible_values = possible_values

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


__all__ = ['IntRandomMutator', 'IntEdgeMutator']
