from typing import Dict, Any
from random import Random

from pycrate_asn1rt.setobj import ASN1Set, ASN1Range

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import IntType


@mutates(IntType)
class IntRandomMutator(Mutator):
    """Mutator for `IntType` objects that gerate random values in the integer boundaries."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume that there is no boundary, so we assume a range like [0, 2^256),
        # later when we get a reference of the particular instance we are working on, we will
        # modify this
        self._range: tuple[int, int] | None = None  # [start, end)
        self._extracted_values: set[int] | None = None

        # for cases in which the range size is =< 256, we directly store each possible value
        self._possible_values: list[int] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `IntRandomMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'range' (optional): The limits of the range values in which values should be
                    generated.
                'extracted_values' (optional): The set of already extracted values.
                'possible_values' (optional): The list of possible values if the range size is =<
                    256.
                'rand_state': The state of the random number generator.
        """

        state = {'rand_state': self._rand.getstate()}

        if self._range is not None:
            state['range'] = self._range
            state['extracted_values'] = self._extracted_values
        elif self._possible_values is not None:
            state['possible_values'] = self._possible_values

        return state

    def _range_limits(self, r: ASN1Range) -> tuple[int, int]:
        """Extracts the range limits from the specified range.

        Args:
            r: The ASN.1 range object from which to extract the limits.

        Returns:
            Tuple[int, int]: A tuple of the form [lower_bound, upper_bound).
        """

        range_limits = (r.lb, r.ub)
        if not r.lb_incl:
            range_limits = (range_limits[0]-1, range_limits[1])
        if r.ub_incl:
            range_limits = (range_limits[0], range_limits[1]+1)
        return range_limits

    def _mutate(self, data: IntType, update_state: bool, state: Dict[str, Any] | None = None) -> Mutation | None:
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

        if state is not None:
            rand.setstate(state['rand_state'])
            range_limits = state.get('range', None)
            extracted_values = state.get('extracted_values', None)
            possible_values = state.get('possible_values', None)
        elif data.constraints and 'val' in data.constraints:
            # try to read the range limits from the data
            ranges = data.constraints['val'].root

            if len(ranges) == 1:
                # a single range, so we can use `range_limits`
                range_limits = self._range_limits(ranges[0])

                if range_limits[1] - range_limits[0] < 256:
                    # there are only a few values, so enumerate them all
                    possible_values = list(
                        range(range_limits[0], range_limits[1]))
                    range_limits = None
                else:
                    extracted_values = set()
            else:
                # multiple ranges, so we have to enumerate all the possible values
                possible_values = []
                for r in ranges:
                    if isinstance(r, ASN1Set):
                        # pylint: disable=protected-access
                        possible_values += r._rr
                        for _r in r._rv:
                            curr_range = self._range_limits(_r)
                            possible_values += list(
                                range(curr_range[0], curr_range[1]))
                    else:
                        curr_range = self._range_limits(_r)
                        possible_values += list(
                            range(curr_range[0], curr_range[1]))

        if range_limits is None and possible_values is None:
            range_limits = (0, 2**256)

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

    def next(self):
        self._mutate(True, None)

    def mutate(self, data: IntType, state: Dict[str, Any] | None = None) -> Mutation:
        return self._mutate(False, data, state)


@mutates(IntType)
class IntEdgeMutator(Mutator):
    """Mutator for `IntType` objects that gerate random values that are at around the edges of the
    allowed range.
    """

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._possible_values: list[int] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `IntRandomMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'possible_values': The list of possible values that haven't been already used.
                'rand_state': The state of the random number generator.
        """

        return {
            'possible_values': self._possible_values,
            'rand_state': self._rand.getstate()
        }

    def _generate_values_from_limits(self, lower_bound: int, upper_bound: int) -> list[int]:
        """Generate edge values given a lower and upper bound.

        Args:
            lower_bound: The lower bound limit.
            upper_bound: The upper bound limit.

        Returns:
            list[int]: A list of values in [lower_bound-2, lower_bound+2] and 
                [upper_bound-2, upper_bound+2].
        """

        # take +2/-2 of the range limits
        possible_values = list(range(lower_bound-2, lower_bound+3))
        possible_values += list(range(upper_bound-2, upper_bound+3))
        return possible_values

    def _generate_from_range(self, r: ASN1Range) -> list[int]:
        """Generate edge values from the specified range.

        Args:
            r: The ASN.1 range object from which to extract the edge values.

        Returns:
            list[int]: A list of values in [lower_bound-2, lower_bound+2] and 
                [upper_bound-2, upper_bound+2].
        """

        curr_range = (r.lb, r.ub)
        if not r.lb_incl:
            curr_range = (curr_range[0]-1, curr_range[1])
        if r.ub_incl:
            curr_range = (curr_range[0], curr_range[1]+1)

        return self._generate_values_from_limits(*curr_range)

    def _mutate(self, data: IntType, update_state: bool, state: Dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        possible_values = self._possible_values

        if possible_values is not None:
            rand.setstate(state['rand_state'])
            possible_values = state['possible_values']
        elif data.constraints and 'val' in data.constraints:
            # try to read the range limits from the data
            ranges = data.constraints['val'].root
            possible_values = []
            for r in ranges:
                if isinstance(r, ASN1Set):
                    # pylint: disable=protected-access
                    for _r in r._rv:
                        possible_values += self._generate_from_range(_r)
                else:
                    possible_values += self._generate_from_range(r)

        if possible_values is None:
            possible_values = self._generate_values_from_limits(0, 2**256)

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

    def mutate(self, data: IntType, state: Dict[str, Any] | None = None) -> Mutation:
        return self._mutate(False, data, state)


__all__ = ['IntRandomMutator', 'IntEdgeMutator']
