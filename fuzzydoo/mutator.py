import hashlib
from typing import Type, Dict, List, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
from random import Random

from .utils.errs import FuzzyDooError


class MutatorCompleted(FuzzyDooError):
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
        field_qualified_name: The qualified name of the field in the `Fuzzable` object that was 
            mutated. This attribute allows for precise tracking of the location of the mutation 
            within the data structure.
        mutated_value: The new value of the mutated field. This attribute holds the 
            value that the field was changed to as part of the mutation. If can be `None` if the 
            new value is not currently available.
    """

    def __init__(self, mutator: type, mutator_state: Any, field_name: str, mutated_value=None):
        """Initialize a `Mutation` object.

        Arguments:
            mutator: The type of the mutator that generated this mutation.
            mutator_state: The state of the mutator at the time of mutation.
            field_name: The  name of the field in the `Fuzzable` object that was mutated.
            mutated_value (optional): The new value of the mutated field. Defaults to `None`.
        """

        self.mutator: type = mutator
        self.mutator_state: Any = mutator_state
        self.field_name: str = field_name
        self.mutated_value = mutated_value

    def __eq__(self, value: object) -> bool:
        return isinstance(value, Mutation) \
            and self.mutator == value.mutator \
            and self.mutator_state == value.mutator_state \
            and self.field_name == value.field_name \
            and self.mutated_value == value.mutated_value

    def apply(self, data):
        """Apply this mutation to the specified `data`.

        Args:
            data: The `Fuzzable` object to which the mutation should be applied.

        Returns:
            The `Fuzzable` object with the mutation applied.
        """

        mutator = self.mutator()
        mutated_val = mutator.mutate(
            data, state=self.mutator_state).mutated_value

        path = data.name if self.field_name == "" else data.name + '.' + self.field_name
        data.set_content_by_path(path, mutated_val)
        return data


class Mutator(ABC):
    """A base class for implementing mutators that can perform mutations over some `Fuzzable` data.

    Mutators are entities that know how to perform specific types of mutations over `Fuzzable` data.
    They are used to generate new test cases by applying random mutations to existing ones.
    """

    def __init__(self, seed: int = 0):
        """Initialize a `Mutator` object.

        Args:
            seed (optional): The seed value to be used for randomization within this mutator. 
                Defaults to `0`.
        """

        self._name: str = self.__class__.__name__
        self._seed: int = seed
        self._rand: Random = Random(
            hashlib.sha512(self._seed.to_bytes()).digest())

    @property
    def name(self) -> str:
        """The name of the mutator."""

        return self._name

    @property
    def seed(self) -> int:
        """The seed value used for randomization within this mutator."""

        return self._seed

    @abstractmethod
    def next(self):
        """Go to the next mutation.

        Raises:
            MutatorCompleted if there are no more mutations available.
        """

    @abstractmethod
    def mutate(self, data, state: Any | None = None) -> Mutation:
        """Perform a random mutation on the specified Fuzzable data.

        Args:
            data: The `Fuzzable` data on which the mutation should be performed.
            state (optional): The state of this mutator to use for this mutation. Defaults to 
                `None`.

        Returns:
            Mutation: A new `Mutation` object representing the random mutation performed on the 
                input data.
        """


MUTATORS: Dict[str, List[Mutator]] = {}


def mutable(cls: Type):
    """Decorator that marks a class as mutable.

    This decorator works together with the `mutates` decorator.

    This decorator registers the class as a key in the `MUTATORS` registry and add an
    implementation for the `mutators` method (see `Fuzzable`).
    """

    key = cls.__module__ + '.' + cls.__name__
    MUTATORS[key] = []

    def old_mutators(_):
        return []

    if hasattr(cls, 'mutators') \
            and (not hasattr(cls, '__abstractmethods__')
                 or 'mutators' not in getattr(cls, '__abstractmethods__')):
        old_mutators = cls.mutators

    def new_mutators(self):
        res = MUTATORS.get(key, [])
        return old_mutators(self) + [(m, self.qualified_name) for m in res]

    cls.mutators = new_mutators

    if hasattr(cls, '__abstractmethods__'):
        cls.__abstractmethods__ = frozenset(
            name for name in cls.__abstractmethods__ if name != 'mutators'
        )

    return cls


def mutates(*args: tuple[Type]):
    """Decorator that specify which types the class is a mutator of.

    This decorator works together with the `mutable` decorator.

    This decorator registers the class as a value in the `MUTATORS` registry in each of the entries 
    specified as argument. If one of the types specified is not marked as mutable with the 
    `mutable` decorator, it will simply be skipped.

    Args:
        *args: The types for which the class is a mutator of.
    """

    def decorator(cls: Type):
        for t in args:
            key = t.__module__ + '.' + t.__name__
            if key not in MUTATORS:
                continue

            MUTATORS[key].append(cls)
        return cls

    return decorator
