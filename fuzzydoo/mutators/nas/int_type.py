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

        # initially we assume that there is no boundary, so we assume a range like [0, 2^256),
        # later when we get a reference of the particular instance we are working on, we will
        # modify this
        self._range: tuple[int, int] | None = None  # [start, end)
        self._extracted_values: set[int] | None = None

        # for cases in which there is a list of predefined values
        self._possible_values: list[int] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `IntRandomMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                `'rand_state'`: The state of the random number generator.
                `'range'` (optional): The limits of the range values in which values should be
                    generated.
                `'extracted_values'` (optional): The set of already extracted values.
                `'possible_values'` (optional): The list of possible values if present.
        """

        state = {'rand_state': self._rand.getstate()}

        if self._range is not None:
            state['range'] = self._range
            if self._extracted_values is not None:
                state['extracted_values'] = set(self._extracted_values)
            else:
                state['extracted_values'] = None
        elif self._possible_values is not None:
            state['possible_values'] = list(self._possible_values)

        return state

    def _mutate(self,
                data: IntType | UintType | IntLEType | UintLEType | None,
                update_state: bool,
                state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        range_limits = self._range
        extracted_values = self._extracted_values
        possible_values = self._possible_values
        set_state = range_limits is None and possible_values is None

        if state is not None:
            rand.setstate(state['rand_state'])
            range_limits = state.get('range', None)
            extracted_values = state.get('extracted_values', None)
            possible_values = state.get('possible_values', None)
        elif set_state:
            if data:
                if data.possible_values:
                    possible_values = data.possible_values
                else:
                    if isinstance(data, (UintType, UintLEType)):
                        limits = (0, 2**data.bit_length)
                    else:
                        limits = signed_integer_limits(data.bit_length)

                    if data.bit_length <= 8:
                        possible_values = list(range(limits[0], limits[1]))
                    else:
                        range_limits = limits
                        extracted_values = set()
            else:
                range_limits = (0, 2**256)
                extracted_values = set()

            self._range = range_limits
            self._extracted_values = extracted_values
            self._possible_values = possible_values

        if possible_values is not None:
            value = rand.choice(possible_values)
        else:
            while True:
                value = rand.randrange(range_limits[0], range_limits[1])
                if value not in extracted_values:
                    break

        if update_state:
            if possible_values is not None:
                self._possible_values.remove(value)
                if len(self._possible_values) == 0:
                    raise MutatorCompleted()
            elif extracted_values is not None:
                self._extracted_values.add(value)
                if len(self._extracted_values) == self._range[1] - self._range[0]:
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
    def mutate(self, data: IntType | UintType | IntLEType | UintLEType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


@mutates(IntType, UintType, IntLEType, UintLEType)
class IntEdgeMutator(Mutator):
    """Mutator for generic integer objects that generate random values that are at around the edges 
    of the allowed range.
    """

    _DELTA = 3

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._possible_values: list[int] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `IntEdgeMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                `'rand_state'`: The state of the random number generator.
                `'possible_values'`: The list of possible values that haven't been already used.
        """

        return {
            'rand_state': self._rand.getstate(),
            'possible_values': list(self._possible_values) if self._possible_values is not None else None
        }

    def _generate_values_from_limits(self, lower_bound: int, upper_bound: int) -> list[int]:
        """Generate edge values given a lower and upper bound.

        Args:
            lower_bound: The lower bound limit.
            upper_bound: The upper bound limit.

        Returns:
            list[int]: A list of values in [lower_bound, lower_bound+2] and 
                [upper_bound-3, upper_bound).
        """

        possible_values = list(range(lower_bound, lower_bound + self._DELTA))
        possible_values += list(range(upper_bound - self._DELTA, upper_bound))
        return possible_values

    def _mutate(self,
                data: IntType | UintType | IntLEType | UintLEType | None,
                update_state: bool,
                state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        possible_values = self._possible_values

        if state is not None:
            rand.setstate(state['rand_state'])
            possible_values = state['possible_values']
        elif data:
            if isinstance(data, (UintType, UintLEType)):
                limits = (0, 2**data.bit_length)
            else:
                limits = signed_integer_limits(data.bit_length)

            if limits[1] - limits[0] <= self._DELTA * 4:
                # it doesn't make sense to apply
                raise MutatorNotApplicable()

            self._possible_values = possible_values = self._generate_values_from_limits(
                limits[0], limits[1])

        if possible_values is None:
            self._possible_values = possible_values = self._generate_values_from_limits(0, 2**256)

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

    @override
    def next(self):
        self._mutate(None, True)

    @override
    def mutate(self, data: IntType | UintType | IntLEType | UintLEType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


__all__ = ['IntRandomMutator', 'IntEdgeMutator']
