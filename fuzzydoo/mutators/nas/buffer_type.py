from typing import Any, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, mutates
from ...proto.nas.types import BufferType


@mutates(BufferType)
class BufferRandomMutator(Mutator):
    """Mutator for `BufferType` objects that generate random values that are not in the list of 
    possible ones.
    """

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._size: int = 0
        self._extracted_values: set[bytes] = set()
        self._last_extracted_value: bytes | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'size'`: The size of the string in bits.
                - `'extracted_values'`: The set of already extracted values.
        """

        return {
            'rand_state': self._rand.getstate(),
            'size': self._size,
            'extracted_values': set(self._extracted_values),
        }

    def _get_allowed_values(self, data: BufferType) -> set[bytes]:
        """Get all the allowed values for the given data type.

        Args:
            data: The data from which to get the allowed values.

        Returns:
            set[bytes]: A set containing all the allowed values for this data. If no specific 
                allowed value exists, an empty set will be returned.
        """

        if not data.possible_values:
            return set()

        possible_values = data.possible_values

        # to apply some encoding or mapping if needed
        mapped_values = set()
        old_value = data.value
        for v in possible_values:
            data.value = v
            mapped_values.add(data.value)

        data.value = old_value
        return mapped_values

    @override
    def next(self):
        self._extracted_values.add(self._last_extracted_value)
        if len(self._extracted_values) == 2**self._size:
            raise MutatorCompleted()

    @override
    def mutate(self, data: BufferType, state: dict[str, Any] | None = None) -> Mutation:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            # if there is a state, load variables from the state
            rand.setstate(state['rand_state'])
            size = state['size']
            extracted_values = state['extracted_values']
            mutator_state = state
        elif not self._extracted_values:
            self._extracted_values = extracted_values = self._get_allowed_values(data)
            self._size = size = data.bit_length
            if len(extracted_values) == 2**size:
                raise MutatorNotApplicable()

            mutator_state = self._export_state()
        else:
            size = self._size
            extracted_values = self._extracted_values
            mutator_state = self._export_state()

        while True:
            self._last_extracted_value = rand.randbytes(size // 8)
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


@mutates(BufferType)
class BufferPartialContentMutator(Mutator):
    """Mutator for `BufferType` objects that generates values with some different bytes w.r.t. the 
    original ones.
    """

    _MAX_RANGE_DELTA = 50
    _SPECIAL_VALUES = [b"\x00", b"\x01", b"\xfe", b"\xff"]

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
        return (start, min(end, start + self._MAX_RANGE_DELTA))

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
            data = data[:i] + rand.choice(self._SPECIAL_VALUES) + data[i + 1:]
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
    def mutate(self, data: BufferType, state: dict[str, Any] | None = None) -> Mutation:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            # if there is a state, load variables from the state
            rand.setstate(state['rand_state'])
            extracted_values = state['extracted_values']
            mutator_state = state
        else:
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

        return Mutation(
            mutator=type(self),
            mutator_state=mutator_state,
            field_name=data.name,
            mutated_value=self._last_extracted_value
        )


__all__ = ['BufferRandomMutator', 'BufferPartialContentMutator']
