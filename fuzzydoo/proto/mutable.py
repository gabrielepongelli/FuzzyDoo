from typing import Callable, Type, Dict, List

from ..fuzzable import Fuzzable
from ..mutator import Mutator


MUTATORS: Dict[str, List[Mutator]] = {}


def mutable_protocol(protocol_name: str) -> Callable:
    """Generates a decorator for the specified protocol.

    Args:
        protocol_name: Name of the protocol to generate the decorator for.

    Returns:
        Callable: The decorator for the specified protocol. This decorator registers the class as a 
            key in the `MUTATORS` registry and add an implementation for the `mutators` method (see 
            `Fuzzable`).
    """

    def decorator(cls: Type[Fuzzable]):
        MUTATORS[protocol_name + '.' + cls.__name__] = []

        def old_mutators(_):
            return []

        if hasattr(cls, 'mutators') \
                and (not hasattr(cls, '__abstractmethods__')
                     or 'mutators' not in getattr(cls, '__abstractmethods__')):
            old_mutators = cls.mutators

        def new_mutators(self):
            res = MUTATORS.get(protocol_name + '.' + cls.__name__, [])
            return old_mutators(self) + [(m, self.qualified_name) for m in res]

        cls.mutators = new_mutators

        if hasattr(cls, '__abstractmethods__'):
            cls.__abstractmethods__ = frozenset(
                name for name in cls.__abstractmethods__ if name != 'mutators'
            )

        return cls

    return decorator
