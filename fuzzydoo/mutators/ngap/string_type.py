from typing import Any, override
from random import Random

from pycrate_asn1rt.setobj import ASN1Range

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.ngap.types import *


@mutates(BitStrType)
class BitStrMutator(Mutator):
    """Mutator for `BitStrType` objects that generate random values."""

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
        """Export the current state of the `BitStrMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'rand_state': The state of the random number generator.
                'bit_len' (optional): The length of the string in bits.
                'range' (optional): The limits of the range values in which values should be
                    generated.
                'extracted_values' (optional): The set of already extracted values.
                'possible_values' (optional): The list of possible values if the range size is =<
                    256.
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

    def _mutate(self, data: BitStrType, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
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
            return Mutation(mutator=type(self),
                            mutator_state=self._export_state(),
                            field_name=data.name,
                            mutated_value=(value, bit_len))

    @override
    def next(self):
        self._mutate(None, True)

    @override
    def mutate(self, data: BitStrType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


@mutates(OctStrType)
class OctStrMutator(Mutator):
    """Mutator for `OctStrType` objects that generate random values."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume a size of 64 bytes, later when we get a reference of the particular
        # instance we are working on, we will modify this
        self._size: int | None = None
        self._extracted_values: set[bytes] | None = None

        # for cases in which the size is = 1, we directly store each possible value
        self._possible_values: list[bytes] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `OctStrMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'rand_state': The state of the random number generator.
                'size' (optional): The size of the string in bytes.
                'extracted_values' (optional): The set of already extracted values.
                'possible_values' (optional): The list of possible values if the range size is =<
                    256.
        """

        state = {'rand_state': self._rand.getstate()}

        if self._size is not None:
            state['size'] = self._size

        if self._extracted_values is not None:
            state['extracted_values'] = set(self._extracted_values)

        if self._possible_values is not None:
            state['possible_values'] = list(self._possible_values)

        return state

    def _mutate(self, data: OctStrType, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
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
            if data and data.constraints and 'sz' in data.constraints:
                # try to read the range limits from the data
                size = data.constraints['sz'].root[0]
                if isinstance(size, ASN1Range):
                    size = size.ub + 1

                if size == 1:
                    # there are only a few values, so enumerate them all
                    possible_values = [i.to_bytes() for i in range(0, 256)]
                else:
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
    def mutate(self, data: OctStrType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


CHAR_RANGES = {
    'ascii': [(0x00, 0x7f)],
    'utf8': [(0x0000, 0xd7ff), (0xe000, 0x10ffff)],
    'utf_16_be': [(0x0000, 0xd7ff), (0xe000, 0x10ffff)],
    'utf_32_be': [(0x0000, 0xd7ff), (0xe000, 0x10ffff)],
    'iso2022_jp_2004': [(0x00, 0x7e), (0x3040, 0x309f), (0x30a0, 0x30ff), (0x4e00, 0x9fff)]
}

TOTAL_CHARS = {
    'ascii': sum(end - start + 1 for start, end in CHAR_RANGES['ascii']),
    'utf8': sum(end - start + 1 for start, end in CHAR_RANGES['utf8']),
    'utf_16_be': sum(end - start + 1 for start, end in CHAR_RANGES['utf_16_be']),
    'utf_32_be': sum(end - start + 1 for start, end in CHAR_RANGES['utf_32_be']),
    'iso2022_jp_2004': sum(end - start + 1 for start, end in CHAR_RANGES['iso2022_jp_2004'])
}


@mutates(StrUtf8Type, StrTeleType, StrT61Type, StrVidType, StrGraphType, StrGeneType, StrUnivType, StrBmpType)
class GenericStrMutator(Mutator):
    """Mutator for generic string objects that generate random strings in their codec."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume a size of 256 bytes, later when we get a reference of the particular
        # instance we are working on, we will modify this
        self._size: int | None = None
        self._codec: str = ""
        self._extracted_values: set[str] = set()

    def _export_state(self) -> dict:
        """Export the current state of the `GenericStrMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'rand_state': The state of the random number generator.
                'extracted_values': The set of already extracted values.
                'codec': The codec to use.
                'size' (optional): The size of the string in bytes.
        """

        state = {
            'rand_state': self._rand.getstate(),
            'extracted_values': set(self._extracted_values),
            'codec': self._codec
        }

        if self._size is not None:
            state['size'] = self._size

        return state

    def _generate_random_string(self, rand: Random, length: int, codec: str) -> str:
        """Generates a random string of the given length.

        Args:
            rand: The random number generator to use.
            length: The desired length of the string.
            codec: The codec to use for the string generation. It must be a key in `CHAR_RANGES`.

        Returns:
            str: The generated random string.
        """

        res = ''
        for _ in range(length):
            chosen_range = rand.choice(CHAR_RANGES[codec])
            code_point = rand.randint(chosen_range[0], chosen_range[1])
            res += chr(code_point)
        return res

    def _mutate(self, data: OctStrType, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        size = self._size
        extracted_values = self._extracted_values
        codec = self._codec
        set_state = codec is None

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            codec = state['codec']
            size = state.get('size', None)
        elif set_state:
            codec = data.codec
            if data and data.constraints and 'sz' in data.constraints:
                # try to read the range limits from the data
                size = data.constraints['sz'].root[0]
                if isinstance(size, ASN1Range):
                    size = (size.lb, size.ub + 1)
                extracted_values = set()

            self._codec = codec
            self._size = size
            self._extracted_values = extracted_values

        while True:
            if size is None:
                length = rand.randint(1, 256)
            elif isinstance(size, tuple):
                length = rand.randint(size[0], size[1])
            else:
                length = size

            value = self._generate_random_string(rand, length, codec)
            if value not in extracted_values:
                break

        if update_state:
            self._extracted_values.add(value)
            if len(self._extracted_values) == TOTAL_CHARS[codec]:
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
    def mutate(self, data: OctStrType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


@mutates(StrNumType, StrPrintType, StrIa5Type, StrVisType, StrIso646Type)
class AlphabetStringMutator(Mutator):
    """Generic mutator for string types objects with a specific alphabet that generate random values."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume a size of 256 bytes, later when we get a reference of the particular
        # instance we are working on, we will modify this
        self._size: int | tuple[int, int] | None = None
        self._extracted_values: set[str] = set()
        self._alphabet: str | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `AlphabetStringMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'rand_state': The state of the random number generator.
                'extracted_values': The set of already extracted values.
                'alphabet': The alphabet used for the string generation.
                'size' (optional): The size of the string in characters.
        """

        state = {
            'rand_state': self._rand.getstate(),
            'extracted_values': set(self._extracted_values),
            'alphabet': self._alphabet
        }

        if self._size is not None:
            state['size'] = self._size

        return state

    def _mutate(self, data: AlphabeticalStringType, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are
        implemented all here, and based on the value of `update_state` this function will behave
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        size = self._size
        extracted_values = self._extracted_values
        alphabet = self._alphabet
        set_state = size is None

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            alphabet = state['alphabet']
            size = state.get('size', None)
        elif set_state:
            if data and data.constraints and 'sz' in data.constraints:
                # try to read the range limits from the data
                size = data.constraints['sz'].root[0]
                if isinstance(size, ASN1Range):
                    size = (size.lb, size.ub + 1)

            self._size = size
            self._extracted_values = extracted_values
            self._alphabet = alphabet = data.alphabet

        while True:
            if size is None:
                length = rand.randint(1, 256)
            elif isinstance(size, tuple):
                length = rand.randint(size[0], size[1])
            else:
                length = size

            value = ''
            for _ in range(length):
                value += rand.choice(alphabet)

            if value not in extracted_values:
                break

        if update_state:
            self._extracted_values.add(value)
            if size is None:
                length = 256
            elif isinstance(size, tuple):
                length = size[1]
            else:
                length = size

            if len(self._extracted_values) == len(alphabet) * length:
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
    def mutate(self, data: AlphabeticalStringType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


__all__ = ['BitStrMutator', 'OctStrMutator',
           'GenericStrMutator', 'AlphabetStringMutator']
