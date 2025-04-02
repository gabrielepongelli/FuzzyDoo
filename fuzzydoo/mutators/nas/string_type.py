from typing import Any, ClassVar, override
from random import Random
from math import ceil

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, mutates
from ...proto.nas.types import StringType
from ...utils.chars import CHAR_RANGES, TOTAL_CHARS


@mutates(StringType)
class StringRandomMutator(Mutator[StringType, str]):
    """Mutator for `StringType` objects that generate random strings in their codec."""

    FIELD_NAME = 'value'

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._extracted_values: set[str] = set()
        self._codec: str | None = None
        self._last_extracted_value: str | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'extracted_values'`: The set of already extracted values.
                - `'codec'`: The codec to use.
        """

        return {
            'rand_state': self._rand.getstate(),
            'extracted_values': set(self._extracted_values),
            'codec': self._codec,
        }

    def _generate_random_string(self, rand: Random, bit_len: int, codec: str) -> str:
        """Generates a random string of the given length.

        Args:
            rand: The random number generator to use.
            bit_len: The desired length of the string in bits.
            codec: The codec to use for the string generation.

        Returns:
            str: The generated random string.
        """

        res = ''
        while bit_len <= len(res.encode(encoding=codec)) * 8:
            chosen_range = rand.choice(CHAR_RANGES[codec])
            code_point = rand.randint(chosen_range[0], chosen_range[1])
            res += chr(code_point)
        return res

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)
        if len(self._extracted_values) == TOTAL_CHARS[self._codec]:
            raise MutatorCompleted()

    @override
    def mutate(self, data: StringType, state: dict[str, Any] | None = None) -> Mutation[str]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            codec = state['codec']
            mutator_state = state
        elif self._codec is None:
            self._codec = codec = data.codec
            extracted_values = set()
            mutator_state = self._export_state()
        else:
            codec = self._codec
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            self._last_extracted_value = self._generate_random_string(rand, len(data.value), codec)
            if self._last_extracted_value not in extracted_values:
                break

        if state is None:
            self._rand = rand

        return Mutation[str](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=self._last_extracted_value
        )


@mutates(StringType)
class StringBadEncodeMutator(Mutator[StringType, str]):
    """Mutator for `StringType` objects that generate strings with some invalid bytes for the codec 
    in use.
    """

    FIELD_NAME = 'value'

    MAX_CHARS: ClassVar[int] = 5

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._extracted_values: set[str] = set()
        self._codec: str | None = None
        self._bad_code_points: list[int] = []
        self._last_extracted_value: str | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'extracted_values'`: The set of already extracted values.
                - `'codec'`: The codec to use.
        """

        return {
            'rand_state': self._rand.getstate(),
            'extracted_values': set(self._extracted_values),
            'codec': self._codec,
        }

    def _generate_bad_code_points(self, codec: str) -> list[int]:
        """Generates a set of bad code points for the given codec.

        Args:
            codec: The codec for which to generate the bad code points.

        Returns:
            list[int]: A list of bad code points.
        """

        allowed_ranges = CHAR_RANGES[codec]
        full_range = [(0, 2**(ceil(allowed_ranges[-1][-1].bit_length() / 8) * 8))]

        bad_codes = set(range(*full_range))
        for start, end in allowed_ranges:
            for i in range(start, end + 1):
                bad_codes.discard(i)

        return list(bad_codes)

    def _replace_random(self, data: str, rand: Random) -> str:
        """Replace some random chars in the given string with bad code points.

        Args:
            data: The string to modify.
            rand: The random number generator to use.

        Returns:
            str: The modified string.
        """

        n_changes = rand.randint(1, self.MAX_CHARS)
        n_changes = min(n_changes, len(data))

        changed_chars_pos = []
        all_pos = list(range(len(data)))
        for _ in range(n_changes):
            idx = rand.choice(all_pos)
            all_pos.remove(idx)
            changed_chars_pos.append(idx)

        new_data = b""
        for idx, c in enumerate(data):
            if idx in changed_chars_pos:
                choice = rand.choice(self._bad_code_points)
                new_data += choice.to_bytes(ceil(choice.bit_length() / 8))
            else:
                new_data += c.encode(encoding=self._codec)

        return new_data.decode('latin1')

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)

    @override
    def mutate(self, data: StringType, state: dict[str, Any] | None = None) -> Mutation[str]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if len(data.value):
            raise MutatorNotApplicable()

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            codec = state['codec']
            mutator_state = state
        elif self._codec is None:
            self._codec = codec = data.codec
            extracted_values = set()
            self._bad_code_points = self._generate_bad_code_points(codec)
            mutator_state = self._export_state()
        else:
            codec = self._codec
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            self._last_extracted_value = self._replace_random(data.value, rand)
            if self._last_extracted_value not in extracted_values:
                break

        if state is None:
            self._rand = rand

        return Mutation[str](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=self._last_extracted_value
        )


__all__ = ['StringRandomMutator', 'StringBadEncodeMutator']
