from typing import Any, override
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, mutates
from ...proto.nas.types import StringType
from ...utils.chars import CHAR_RANGES, TOTAL_CHARS


@mutates(StringType)
class StringMutator(Mutator):
    """Mutator for generic string objects that generate random strings in their codec."""

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # initially we assume a size of 256 bytes, later when we get a reference of the particular
        # instance we are working on, we will modify this
        self._size: int | None = None
        self._codec: str | None = None
        self._extracted_values: set[str] | None = None

        # for cases in which there is a list of allowed values
        self._possible_values: list[bytes] | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `GenericStrMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                `'rand_state'`: The state of the random number generator.
                `'extracted_values'`: The set of already extracted values.
                `'codec'`: The codec to use.
                `'size'` (optional): The size of the string in bytes.
        """

        state = {'rand_state': self._rand.getstate()}

        if self._extracted_values is not None:
            state['extracted_values'] = set(self._extracted_values)
            state['size'] = self._size
            state['codec'] = self._codec

        if self._possible_values is not None:
            state['possible_values'] = list(self._possible_values)

        return state

    def _generate_random_string(self, rand: Random, bit_len: int, codec: str) -> str:
        """Generates a random string of the given length.

        Args:
            rand: The random number generator to use.
            bit_len: The desired length of the string in bits.
            codec: The codec to use for the string generation. It must be a key in `CHAR_RANGES`.

        Returns:
            str: The generated random string.
        """

        res = ''
        while bit_len <= len(res.encode(encoding=codec)) * 8:
            chosen_range = rand.choice(CHAR_RANGES[codec])
            code_point = rand.randint(chosen_range[0], chosen_range[1])
            res += chr(code_point)
        return res

    def _mutate(self, data: StringType | None, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
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
        possible_values = self._possible_values
        set_state = extracted_values is None and possible_values is None

        if state is not None:
            rand.setstate(state['rand_state'])
            extracted_values = state.get('extracted_values', None)
            codec = state.get('codec', None)
            size = state.get('size', None)
            possible_values = state.get('possible_values', None)
        elif set_state:
            if data:
                codec = data.codec
                if data.possible_values:
                    possible_values = data.possible_values
                else:
                    size = data.bit_length
                    extracted_values = set()

            self._codec = codec
            self._size = size
            self._extracted_values = extracted_values
            self._possible_values = possible_values

        if possible_values is not None:
            value = rand.choice(possible_values)
        else:
            while True:
                value = self._generate_random_string(rand, size, codec)
                if value not in extracted_values:
                    break

        if update_state:
            if possible_values is not None:
                self._possible_values.remove(value)
                if len(self._possible_values) == 0:
                    raise MutatorCompleted()
            elif extracted_values is not None:
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
    def mutate(self, data: StringType, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(data, False, state)


__all__ = ['StringMutator']
