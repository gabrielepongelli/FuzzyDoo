from typing import Any, override, ClassVar
from random import Random

from ..mutator import Mutator, Mutation, MutatorCompleted, mutates
from ..protocol import Message


# TODO: import these values from some configs

MAX_COPIES = 10
MAX_DELAY = 120  # seconds


@mutates(Message)
class DelayedMessageMutator(Mutator[Message, int]):
    """Mutator for `Message` objects that delays their sending."""

    FIELD_NAME: ClassVar[str] = "delay"

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._delay_values = list(range(1, MAX_DELAY))
        self._last_extracted_value: int | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `MessageMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'delay_values'`: A list containing the remaining values to be mutated.
                - `'rand_state'`: The state of the random number generator.
        """

        return {
            'delay_values': list(self._delay_values),
            'rand_state': self._rand.getstate(),
        }

    @override
    def next(self):
        self._delay_values.remove(self._last_extracted_value)
        if len(self._delay_values) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: Message, state: dict[str, Any] | None = None) -> Mutation[int]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            delay_values = state['delay_values']
            rand.setstate(state['rand_state'])
            mutator_state = state
        else:
            delay_values = self._delay_values
            mutator_state = self._export_state()

        self._last_extracted_value = rand.choice(delay_values)

        if state is None:
            self._rand = rand

        return Mutation[int](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            mutated_value=self._last_extracted_value
        )


@mutates(Message)
class ReplayedMessageMutator(Mutator[Message, int]):
    """Mutator for `Message` objects that sends multiple replicas of the message."""

    FIELD_NAME: ClassVar[str] = "n_replay"

    def __init__(self, seed: int = 0):
        super().__init__(seed)

        self._reply_values = list(range(1, MAX_COPIES))
        self._last_extracted_value: int | None = None

    def _export_state(self) -> dict:
        """Export the current state of the `MessageMutator`.

        Returns:
            dict: A dictionary containing the following keys:
                - `'reply_values'`: A list containing the remaining values to be mutated.
                - `'rand_state'`: The state of the random number generator.
        """

        return {
            'reply_values': list(self._reply_values),
            'rand_state': self._rand.getstate(),
        }

    @override
    def next(self):
        self._reply_values.remove(self._last_extracted_value)
        if len(self._reply_values) == 0:
            raise MutatorCompleted()

    @override
    def mutate(self, data: Message, state: dict[str, Any] | None = None) -> Mutation[int]:
        rand = Random()
        rand.setstate(self._rand.getstate())
        mutator_state: dict

        if state is not None:
            reply_values = state['reply_values']
            rand.setstate(state['rand_state'])
            mutator_state = state
        else:
            reply_values = self._reply_values
            mutator_state = self._export_state()

        self._last_extracted_value = rand.choice(reply_values)

        if state is None:
            self._rand = rand

        return Mutation[int](
            mutator=type(self),
            mutator_state=mutator_state,
            qname=data.qualified_name,
            field_name=self.FIELD_NAME,
            mutated_value=self._last_extracted_value
        )


__all__ = ['DelayedMessageMutator', 'ReplayedMessageMutator']
