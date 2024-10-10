from typing import Type, Dict, List

from ...fuzzable import Fuzzable
from ...mutator import Mutator


PROTOCOL_NAME: str = 'ngap'

MUTATORS: Dict[str, List[Mutator]] = {}


def mutable(cls: Type[Fuzzable]):
    """Decorator that marks a class as mutable.

    This decorator registers the class as a key in the `MUTATORS` registry and add an
    implementation for the `mutators` method (see `Fuzzable`).
    """

    MUTATORS[PROTOCOL_NAME + '.' + cls.__name__] = []

    def old_mutators(_):
        return []

    if hasattr(cls, 'mutators') \
            and (not hasattr(cls, '__abstractmethods__')
                 or 'mutators' not in getattr(cls, '__abstractmethods__')):
        old_mutators = cls.mutators

    def new_mutators(self):
        res = MUTATORS.get(PROTOCOL_NAME + '.' + cls.__name__, [])
        return old_mutators(self) + [(m, self.qualified_name) for m in res]

    cls.mutators = new_mutators

    if hasattr(cls, '__abstractmethods__'):
        cls.__abstractmethods__ = frozenset(
            name for name in cls.__abstractmethods__ if name != 'mutators'
        )

    return cls
