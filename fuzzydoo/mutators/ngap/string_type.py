from typing import Any, ClassVar, override
from random import Random
from math import ceil

from pycrate_asn1rt.setobj import ASN1Range

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, mutates
from ...utils.chars import TOTAL_CHARS, CHAR_RANGES
from ...proto.ngap.types import *


@mutates(BitStrType)
class BitStrMutator(Mutator[BitStrType, tuple[int, int]]):
    """Mutator for `BitStrType` objects that generate random values."""

    FIELD_NAME = 'value'

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume that there is no boundary, so we assume a range like [0, 2^256),
        # later when we get a reference of the particular instance we are working on, we will
        # modify this
        self._bit_len: int | None = None
        self._range: tuple[int, int] | None = None  # [start, end)
        self._extracted_values: set[int] | None = None

        # for cases in which the range size is =< 256, we directly store each possible value
        self._possible_values: list[int] | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'bit_len'` (optional): The length of the string in bits.
                - `'range'` (optional): The limits of the range values in which values should be
                        generated.
                - `'extracted_values'` (optional): The set of already extracted values.
                - `'possible_values'` (optional): The list of possible values if the range size is 
                        =< 256.
        """

        state = {'rand_state': self._rand.getstate()}

        if self._bit_len is not None:
            state['bit_len'] = self._bit_len

        if self._range is not None:
            state['range'] = self._range
            if self._extracted_values is not None:
                state['extracted_values'] = set(self._extracted_values)
            else:
                state['extracted_values'] = None
        elif self._possible_values is not None:
            state['possible_values'] = list(self._possible_values)

        return state

    def _mutate(self, data: BitStrType | None, update_state: bool, state: dict[str, Any] | None = None) -> Mutation[tuple[int, int]] | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        bit_len = self._bit_len
        range_limits = self._range
        extracted_values = self._extracted_values
        possible_values = self._possible_values
        set_state = range_limits is None and possible_values is None

        if state is not None:
            rand.setstate(state['rand_state'])
            bit_len = state.get('bit_len', None)
            range_limits = state.get('range', None)
            extracted_values = state.get('extracted_values', None)
            possible_values = state.get('possible_values', None)
        elif set_state:
            if data and data.constraints and 'sz' in data.constraints:
                # try to read the range limits from the data
                bit_len = data.constraints['sz'].root[0]
                if isinstance(bit_len, ASN1Range):
                    range_limits = (2**bit_len.lb, (2**(bit_len.ub + 1)) - 1)
                    bit_len = bit_len.ub
                else:
                    range_limits = (0, 2**bit_len)

                if range_limits[1] - range_limits[0] < 256:
                    # there are only a few values, so enumerate them all
                    possible_values = list(
                        range(range_limits[0], range_limits[1]))
                    range_limits = None
                else:
                    extracted_values = set()

            else:
                bit_len = 256
                range_limits = (0, 2**256)
                extracted_values = set()

            self._bit_len = bit_len
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
            return Mutation[tuple[int, int]](
                mutator=type(self),
                mutator_state=self._export_state(),
                qname=data.qualified_name,
                field_name=self.FIELD_NAME,
                original_value=data.value,
                mutated_value=(value, bit_len)
            )

    @override
    def next(self):
        self._mutate(None, True)

    @override
    def mutate(self, data: BitStrType, state: dict[str, Any] | None = None) -> Mutation[tuple[int, int]]:
        return self._mutate(data, False, state)


@mutates(OctStrType)
class OctStrRandomMutator(Mutator[OctStrType, bytes]):
    """Mutator for `OctStrType` objects that generate random values that are not in the list of 
    possible ones.
    """

    FIELD_NAME = 'value'

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._sizes: list[int] = []
        self._extracted_values: list[set[bytes]] = []
        self._last_extracted_value: tuple[int, bytes] | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'sizes'`: The possible sizes of the string in bits.
                - `'extracted_values'`: The list of already extracted values for each possible size.
        """

        return {
            'rand_state': self._rand.getstate(),
            'sizes': list(self._sizes),
            'extracted_values': [set(x) for x in self._extracted_values],
        }

    def _get_allowed_values(self, data: OctStrType, size: int) -> set[bytes]:
        """Get all the allowed values for the given data type.

        Args:
            data: The data from which to get the allowed values.
            size: The size of the values to that will be considered.

        Returns:
            set[bytes]: A set containing all the allowed values for this data. If no specific 
                allowed value exists, an empty set will be returned.
        """

        return set(filter(lambda v: len(v) == size, data.possible_values))

    @override
    def next(self):
        size_idx, val = self._last_extracted_value
        self._extracted_values[size_idx].add(val)

        # remove a range if all its values were extracted
        if len(self._extracted_values[size_idx]) == self._sizes[size_idx]:
            del self._sizes[size_idx]
            del self._extracted_values[size_idx]

        if len(self._sizes) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: OctStrType, state: dict[str, Any] | None = None) -> Mutation[bytes]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            # if there is a state, load variables from the state
            rand.setstate(state['rand_state'])
            sizes = state['sizes']
            extracted_values = state['extracted_values']
            mutator_state = state
        elif not self._extracted_values:
            self._sizes = sizes = data.possible_sizes
            if not sizes:
                # every value is allowed
                raise MutatorNotApplicable()

            for s in sizes:
                self._extracted_values.append(self._get_allowed_values(data, s))
            extracted_values = self._extracted_values

            mutator_state = self._export_state()
        else:
            sizes = self._sizes
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            size_idx = rand.randrange(0, len(sizes))
            size = sizes[size_idx]
            val = rand.randbytes(size)
            if val not in extracted_values[size_idx]:
                self._last_extracted_value = (size_idx, val)
                break

        if state is None:
            self._rand = rand

        return Mutation[bytes](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=val
        )


@mutates(OctStrType)
class OctStrPartialContentMutator(Mutator[OctStrType, bytes]):
    """Mutator for `OctStrType` objects that generates values with some different bytes w.r.t. 
    the original ones.
    """

    FIELD_NAME = 'value'

    MAX_RANGE_DELTA: ClassVar[int] = 50

    SPECIAL_VALUES: ClassVar[list[str]] = [b"\x00", b"\x01", b"\xfe", b"\xff"]

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._extracted_values: set[bytes] = set()
        self._last_extracted_value: bytes | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'extracted_values'`: The set of already extracted values.
        """

        return {
            'rand_state': self._rand.getstate(),
            'extracted_values': set(self._extracted_values),
        }

    def _random_range(self, size: int, rand: Random) -> tuple[int, int]:
        """Pick a random sub-range in `[0, size]`.

        Args:
            size: The maximum size of the original range.
            rand: The random number generator to use.

        Returns:
            tuple[int, int]: The start and end indices of the random sub-range.
        """

        val1 = rand.randint(0, size)
        val2 = rand.randint(0, size)
        start, end = (min(val1, val2), max(val1, val2))
        return (start, min(end, start + self.MAX_RANGE_DELTA))

    def _range_to_random(self, data: bytes, rand: Random) -> bytes:
        """Change a random sequence of bytes in the buffer.

        Args:
            data: The buffer to modify.
            rand: The random number generator to use.

        Returns:
            bytes: The modified buffer.
        """

        start, end = self._random_range(len(data), rand)
        return data[:start] + rand.randbytes(end - start) + data[end:]

    def _range_to_special(self, data: bytes, rand: Random) -> bytes:
        """Change a random sequence of bytes in the buffer to some special values.

        Args:
            data: The buffer to modify.
            rand: The random number generator to use.

        Returns:
            bytes: The modified buffer.
        """

        start, end = self._random_range(len(data), rand)
        for i in range(start, end):
            data = data[:i] + rand.choice(self.SPECIAL_VALUES) + data[i + 1:]
        return data

    def _range_to_null(self, data: bytes, rand: Random) -> bytes:
        """Change a random sequence of bytes to null bytes.

        Args:
            data: The buffer to modify.
            rand: The random number generator to use.

        Returns:
            bytes: The modified buffer.
        """

        start, end = self._random_range(len(data), rand)
        return data[:start] + b"\x00" * (end - start) + data[end:]

    def _range_to_de_null(self, data: bytes, rand: Random) -> bytes:
        """Change all zero's in a random range to something else.

        Args:
            data: The buffer to modify.
            rand: The random number generator to use.

        Returns:
            bytes: The modified buffer.
        """

        start, end = self._random_range(len(data), rand)
        for i in range(start, end):
            if data[i] == 0:
                data = data[:i] + rand.randint(1, 255).to_bytes() + data[i + 1:]
        return data

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)

    @override
    def mutate(self, data: OctStrType, state: dict[str, Any] | None = None) -> Mutation[bytes]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            # if there is a state, load variables from the state
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            mutator_state = state
        else:
            if len(data.value) == 0:
                raise MutatorNotApplicable()
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            mutation_func = rand.choice([
                self._range_to_random,
                self._range_to_special,
                self._range_to_null,
                self._range_to_de_null,
            ])
            self._last_extracted_value = mutation_func(data.value, rand)
            if self._last_extracted_value not in extracted_values:
                break

        if state is None:
            self._rand = rand

        return Mutation[bytes](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=self._last_extracted_value
        )


@mutates(BaseStringType)
class StringRandomMutator(Mutator[BaseStringType, str]):
    """Mutator for `BaseStringType` objects that generate random strings in their codec."""

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
    def mutate(self, data: BaseStringType, state: dict[str, Any] | None = None) -> Mutation[str]:
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


@mutates(BaseStringType)
class StringBadEncodeMutator(Mutator[BaseStringType, str]):
    """Mutator for `StringType` objects that generate strings with some invalid bytes for the codec 
    in use.
    """

    FIELD_NAME = "value"

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
    def mutate(self, data: BaseStringType, state: dict[str, Any] | None = None) -> Mutation[str]:
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


__all__ = ['BitStrMutator', 'OctStrRandomMutator', 'OctStrPartialContentMutator',
           'StringRandomMutator', 'StringBadEncodeMutator']
