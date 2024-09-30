import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from random import Random
from typing import Any

from .fuzzable import Fuzzable


class MutatorCompleted(Exception):
    """Exception raised when a mutator has generated all of its possible mutations."""


@dataclass
class Mutation:
    """Represents a mutation of a message.

    This class is used to store information about a mutation performed on a specific field of a 
    `Fuzzable` object. It encapsulates the details of the mutation in such a way that it can be 
    easily replicated and applied to other `Fuzzable` objects.

    Attributes:
        mutator: The type of the mutator that generated this mutation. This attribute helps
            identify the type of mutation that was performed.
        mutator_state: The state of the mutator at the time of mutation. This attribute can hold
            any additional information about the mutator's state that might be useful for applying 
            the mutation.
        field_path: The path to the field in the `Fuzzable` object that was mutated. This attribute 
            allows for precise tracking of the location of the mutation within the data structure.
        mutated_value: The new value of the mutated field. This attribute holds the value that the 
            field was changed to as part of the mutation.
    """

    mutator: type
    mutator_state: Any
    field_path: str
    mutated_value: Any

    def __eq__(self, value: object) -> bool:
        return isinstance(value, Mutation) \
            and self.mutator == value.mutator \
            and self.mutator_state == value.mutator_state \
            and self.field_path == value.field_path \
            and self.mutated_value

    def apply(self, data: Fuzzable) -> Fuzzable:
        """Apply this mutation to the specified `data`.

        Args:
            data: The `Fuzzable` object to which the mutation should be applied.

        Returns:
            The `Fuzzable` object with the mutation applied.
        """

        mutator = self.mutator()
        new_mutation = mutator.mutate(
            data, state=self.mutator_state).mutated_value
        data.set_content_by_path(self.field_path, new_mutation.mutated_value)
        return data


class Mutator(ABC):
    """A base class for implementing mutators that can perform mutations over some `Fuzzable` data.

    Mutators are entities that know how to perform specific types of mutations over `Fuzzable` data.
    They are used to generate new test cases by applying random mutations to existing ones.

    Attributes:
        name: The name of the mutator. This attribute is automatically set to the name of the 
            subclass that inherits from `Mutator`.
        seed: The seed value to be used for randomization within this mutator. Defaults to `0`.
    """

    def __init__(self, seed: int = 0):
        self.name: str = self.__class__.__name__
        self.seed: int = seed
        self._rand: Random = Random(hashlib.sha512(self.seed).digest())

    @abstractmethod
    def next(self):
        """Go to the next mutation.

        Raises:
            MutatorCompleted if there are no more mutations available.
        """

    @abstractmethod
    def mutate(self, data: Fuzzable, rand: Random | None = None, state: Any | None = None) -> Mutation:
        """Perform a random mutation on the specified Fuzzable data.

        Args:
            data: The `Fuzzable` data on which the mutation should be performed.
            rand (optional): A random number generator to be used for this mutation. Defaults to 
                `None`.
            state (optional): The state of this mutator to use for this mutation. Defaults to 
                `None`.

        Returns:
            Mutation: A new `Mutation` object representing the random mutation performed on the 
                input data.
        """
