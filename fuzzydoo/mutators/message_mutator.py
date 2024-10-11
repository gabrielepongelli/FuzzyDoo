from typing import Any, Dict
from random import Random

from ..mutator import Mutator, Mutation, MutatorCompleted, mutates
from ..fuzzable import Fuzzable
from ..proto.message import Message


# TODO: import these values from some configs

MAX_COPIES = 10
MAX_DELAY = 120  # seconds


@mutates(Message)
class MessageMutator(Mutator):
    """Mutator for `Message` objects.

    This mutator knows how to mutate generic messages. In particular, it will mutate one field 
    between `n_replay` and `delay` fields (chosen at random).
    """

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        # these are respectively the field name and the possible values
        self._reply_values = ("n_replay", list(range(MAX_COPIES)))
        self._delay_values = ("delay", list(range(MAX_DELAY)))

    def _export_state(self) -> dict:
        """Export the current state of the `MessageMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'reply_values': A tuple containing the field name 'n_replay' and the remaining 
                               values to be mutated.
                'delay_values': A tuple containing the field name 'delay' and the remaining 
                               values to be mutated.
                'rand_state': The state of the random number generator.
        """

        return {
            'reply_values': self._reply_values,
            'delay_values': self._delay_values,
            'rand_state': self._rand.getstate(),
        }

    def _mutate(self, update_state: bool, _, state: Dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are 
        implemented all here, and based on the value of `update_state` this function will behave 
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        reply_values = self._reply_values
        delay_values = self._delay_values

        if state is not None:
            reply_values = state['reply_values']
            delay_values = state['delay_values']
            rand.setstate(state['rand_state'])

        mutation_type = rand.choice([reply_values, delay_values])
        mutation_value = rand.choice(mutation_type[1])

        if update_state:
            mutation_type[1].remove(mutation_value)
            self._rand.setstate(rand.getstate())
            if len(self._delay_values[1]) == 0 and len(self._reply_values[1]) == 0:
                raise MutatorCompleted()
        else:
            return Mutation(mutator=type(self),
                            mutator_state=self._export_state(),
                            field_name=mutation_type[0],
                            mutated_value=mutation_value)

    def next(self):
        self._mutate(True, None)

    def mutate(self, data: Fuzzable, state: Dict[str, Any] | None = None) -> Mutation:
        return self._mutate(False, data, state)


__all__ = ['MessageMutator']
