from typing import Any, override
from random import Random

from ..mutator import Mutator, Mutation, MutatorCompleted, mutates
from ..proto.message import Message


# TODO: import these values from some configs

MAX_COPIES = 10
MAX_DELAY = 120  # seconds


@mutates(Message)
class DelayedMessageMutator(Mutator):
    """Mutator for `Message` objects that delays their sending."""

    _FIELD_NAME = "delay"

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._delay_values = list(range(1, MAX_DELAY))

    def _export_state(self) -> dict:
        """Export the current state of the `MessageMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'delay_values': A list containing the remaining values to be mutated.
                'rand_state': The state of the random number generator.
        """

        return {
            'delay_values': self._delay_values,
            'rand_state': self._rand.getstate(),
        }

    def _mutate(self, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are 
        implemented all here, and based on the value of `update_state` this function will behave 
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        delay_values = self._delay_values

        if state is not None:
            delay_values = state['delay_values']
            rand.setstate(state['rand_state'])

        value = rand.choice(delay_values)

        if update_state:
            self._delay_values.remove(value)
            self._rand.setstate(rand.getstate())
            if len(self._delay_values) == 0:
                raise MutatorCompleted()
        else:
            return Mutation(mutator=type(self),
                            mutator_state=self._export_state(),
                            field_name=self._FIELD_NAME,
                            mutated_value=value)

    @override
    def next(self):
        self._mutate(True, None)

    @override
    def mutate(self, _, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(False, state)


@mutates(Message)
class ReplayedMessageMutator(Mutator):
    """Mutator for `Message` objects that sends multiple replicas of the message."""

    _FIELD_NAME = "n_replay"

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._reply_values = list(range(1, MAX_COPIES))

    def _export_state(self) -> dict:
        """Export the current state of the `MessageMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                'reply_values': A list containing the remaining values to be mutated.
                'rand_state': The state of the random number generator.
        """

        return {
            'reply_values': self._reply_values,
            'rand_state': self._rand.getstate(),
        }

    def _mutate(self, update_state: bool, state: dict[str, Any] | None = None) -> Mutation | None:
        """Helper method for `mutate` and `next`.

        Since the operations performed for `mutate` and `next` are almost identical, they are 
        implemented all here, and based on the value of `update_state` this function will behave 
        like `next` (`True`) or `mutate` (`False`).
        """

        rand = Random()
        rand.setstate(self._rand.getstate())
        reply_values = self._reply_values

        if state is not None:
            reply_values = state['reply_values']
            rand.setstate(state['rand_state'])

        value = rand.choice(reply_values)

        if update_state:
            self._reply_values.remove(value)
            self._rand.setstate(rand.getstate())
            if len(self._reply_values) == 0:
                raise MutatorCompleted()
        else:
            return Mutation(mutator=type(self),
                            mutator_state=self._export_state(),
                            field_name=self._FIELD_NAME,
                            mutated_value=value)

    @override
    def next(self):
        self._mutate(True, None)

    @override
    def mutate(self, _, state: dict[str, Any] | None = None) -> Mutation:
        return self._mutate(False, state)


__all__ = ['DelayedMessageMutator', 'ReplayedMessageMutator']
