from typing import Any, ClassVar, Sequence, override, Generic
from random import Random

from ...mutator import Mutator, Mutation, MutatorCompleted, MutatorNotApplicable, mutates
from ...proto.ngap.types import SequenceType, DataT


@mutates(SequenceType)
class SequenceLengthMutator(Mutator[SequenceType[DataT], Sequence], Generic[DataT]):
    """Mutator for `SequenceType` objects that expands or reduces the length of the sequence such 
    that `[len-N, len)` and in `(len, len+N]`, where `len` is the original length of the sequence.
    """

    FIELD_NAME = 'value'

    DELTA: ClassVar[int] = 10

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._possible_deltas: list[int] = []
        self._last_extracted_delta: int | None = None

    def _export_state(self) -> dict:
        """Export the current state.

        Returns:
            dict: A dictionary containing the following keys:
                - `'rand_state'`: The state of the random number generator.
                - `'possible_deltas'`: The list of possible length deltas that can be extracted.
        """

        return {
            'rand_state': self._rand.getstate(),
            'possible_deltas': list(self._possible_deltas),
        }

    @override
    def next(self):
        self._possible_deltas.remove(self._last_extracted_delta)
        if len(self._possible_deltas) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: SequenceType[DataT], state: dict[str, Any] | None = None) -> Mutation[Sequence]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            # if there is a state, load variables from the state
            rand.setstate(state['rand_state'])
            possible_deltas = state['possible_deltas']
            mutator_state = state
        elif not self._possible_deltas:
            if len(data.value) < self.DELTA:
                raise MutatorNotApplicable()
            possible_deltas = []
            old_len = len(data.value)
            for new_len in range(old_len + 1, old_len + self.DELTA + 1):
                delta = new_len - old_len
                possible_deltas.append(delta)
            for new_len in range(old_len - 1, old_len - self.DELTA - 1, -1):
                if new_len < 0:
                    break
                delta = new_len - old_len
                possible_deltas.append(delta)
            self._possible_deltas = possible_deltas

            mutator_state = self._export_state()
        else:
            possible_deltas = self._possible_deltas
            mutator_state = self._export_state()

        self._last_extracted_delta = rand.choice(possible_deltas)
        if self._last_extracted_delta < 0:
            # remove some items
            delta = -self._last_extracted_delta
            new_value = data.value[:len(data.value) - delta]
        else:
            # add some items
            new_value = data.value + (data.value[-1:] * self._last_extracted_delta)

        if state is None:
            self._rand = rand

        return Mutation[Sequence](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            original_value=data.value,
            mutated_value=new_value
        )


__all__ = ['SequenceLengthMutator']
