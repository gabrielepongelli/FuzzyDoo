import operator
from typing import Any, override
from random import Random
from functools import reduce

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import TimeUTCType, TimeGenType


RANGES = {
    'year': (0, 10000),
    'month': (0, 100),
    'day': (0, 100),
    'hour': (0, 100),
    'minute': (0, 100),
    'second': (0, 100),
    'fraction': (0, 1000000000),
}

# NOTE: This is not the exact amount, but an approximation
UTC_TOTAL = reduce(operator.mul, [v[1] - v[0]
                   for k, v in RANGES.items() if k != 'fraction'])

# NOTE: This is not the exact amount, but an approximation
GENERIC_TOTAL = reduce(operator.mul, [v[1] - v[0] for k, v in RANGES.items()])


@mutates(TimeUTCType, TimeGenType)
class TimeMutator(Mutator[TimeUTCType | TimeGenType, tuple]):
    """Mutator for generic time objects that generate random dates."""

    FIELD_NAME = 'value'

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._utc: bool | None = None
        self._extracted_values: set[tuple] = set()

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'utc'`: Whether the time to generate is an TimeUTC or not.
                - `'extracted_values'`: The set of already extracted values.
        """

        return {
            'rand_state': self._rand.getstate(),
            'utc': self._utc,
            'extracted_values': set(self._extracted_values)
        }

    def _generate_random_time(self, rand: Random, utc: bool) -> tuple:
        """Generates a random string of the given length.

        Args:
            rand: The random number generator to use.
            utc: Whether the time to generate is an TimeUTC or not.

        Returns:
            tuple: The generated random time.
        """

        # utc: (YYYY, MM, DD, HH, MM, [SS,] Z)
        # general: (YYYY, MM, DD, HH, [MM, [SS,]][{., }F*,][Z])
        res = {}
        for k, v in RANGES.items():
            if (not utc and k == 'minute' and rand.choice([True, False])) \
                    or (k == 'second' and rand.choice([True, False])) \
                    or (utc and k == 'fraction')\
                    or (not utc and k == 'fraction' and rand.choice([True, False])):
                res[k] = None
                continue

            part = rand.randrange(v[0], v[1])
            res[k] = str(part)

        zone = ''
        if not utc and rand.choice([True, False]):
            zone = None
        elif rand.choice([True, False]):
            zone = 'Z'
        else:
            if not utc and rand.choice([True, False]):
                minute = ''
            else:
                limits = RANGES['minute']
                minute = rand.randrange(limits[0], limits[1])

            limits = RANGES['hour']
            hour = rand.randrange(limits[0], limits[1])

            sign = rand.choice(['', '+', '-'])
            zone = f"{sign}{hour}{minute}"
        res['zone'] = zone

        if utc:
            return (res['year'],
                    res['month'],
                    res['day'],
                    res['hour'],
                    res['minute'],
                    res['second'],
                    res['zone'])

        return (res['year'],
                res['month'],
                res['day'],
                res['hour'],
                res['minute'],
                res['second'],
                res['fraction'],
                res['zone'])

    def _mutate(self, data: TimeUTCType | TimeGenType | None, update_state: bool, state: dict[str, Any] | None = None) -> Mutation[tuple] | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        utc = self._utc
        extracted_values = set(self._extracted_values)
        set_state = utc is None

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
        elif set_state:
            self._utc = utc = isinstance(data, TimeUTCType)

        while True:
            value = self._generate_random_time(rand, utc)
            if value not in extracted_values:
                break

        if update_state:
            self._extracted_values.add(value)
            tot = UTC_TOTAL if utc else GENERIC_TOTAL
            if len(self._extracted_values) == tot:
                raise MutatorCompleted()
        else:
            return Mutation[tuple](
                mutator=type(self),
                mutator_state=self._export_state(),
                qname=data.qualified_name,
                field_name=self.FIELD_NAME,
                original_value=data.value,
                mutated_value=value
            )

    @override
    def next(self):
        self._mutate(None, True)

    @override
    def mutate(self, data: TimeUTCType | TimeGenType, state: dict[str, Any] | None = None) -> Mutation[tuple]:
        return self._mutate(data, False, state)


__all__ = ['TimeMutator']
