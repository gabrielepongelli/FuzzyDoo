from abc import ABC, abstractmethod
from typing import List, Any, Type

from .mutator import Mutator


class Fuzzable(ABC):
    """Represent an entity that can be fuzzed, i.e., whose content (part of or all) can be mutated.

    The Fuzzable class provides a base structure for defining fuzzable entities, i.e. parts of a 
    message that can be altered during the fuzzing process.

    Attributes:
        is_modified: Indicates whether the current fuzzable entity has been modified or not. 
            Defaults to `False`.
    """

    def __init__(self):
        """Initialize a Fuzzable entity."""

        self.is_modified: bool = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the fuzzable entity.

        Returns:
            str: The name of the fuzzable entity.
        """

    @property
    @abstractmethod
    def size(self) -> int:
        """Get the size of the current fuzzable entity in bytes.

        Returns:
            int: The size of the current fuzzable entity in bytes.
        """

    @property
    @abstractmethod
    def bit_length(self) -> int:
        """Get the bit length of the current fuzzable entity.

        Returns:
            int: The bit length of the current fuzzable entity.
        """

    @property
    @abstractmethod
    def fuzzable(self) -> bool:
        """Check if the current fuzzable entity is fuzzable.

        Returns:
            bool: `True` if the current fuzzable entity can be fuzzed, `False` otherwise.
        """

        return True

    @property
    @abstractmethod
    def parent(self) -> "Fuzzable" | None:
        """Get the parent fuzzable entity."""

    @property
    def qualified_name(self) -> str:
        """Get the fully qualified name of the fuzzable entity.

        The qualified name is a string that represents the path to the fuzzable entity 
        in the structure. It is constructed by concatenating the names of all parent 
        entities and the current entity, separated by dots.

        Returns:
            str: The fully qualified name of the fuzzable entity.
        """

        return self.name if self.parent is None else f"{self.parent.qualified_name}.{self.name}"

    @abstractmethod
    def mutators(self) -> List[Type["Mutator"]]:
        """Get all the mutators associated with this fuzzable entity.

        This method is intended to be overridden in subclasses to provide a list of mutator classes 
        that can be used to mutate the content of this fuzzable entity. Each mutator class should 
        be a subclass of `Mutator`.

        Returns:
            List[Type[Mutator]]: A list of mutator classes associated with this fuzzable entity.
        """

    def get_content_by_path(self, path: str) -> "Fuzzable":
        """Get the value of the fuzzable entity at the specified `path`.

        Args:
            path: Path to the fuzzable entity in the structure. The path is a string consisting of 
                the names of the fuzzable entities separated by dots. For example,
                `"parent.child.grandchild"`.

        Returns:
            Fuzzable: The fuzzable entity at the specified `path`.

        Raises:
            AttributeError: If the root entity in the path does not match the current entity's name 
                or if the path does not lead to an existing attribute.
        """

        parts = path.split(".")

        if parts[0] != self.name:
            raise AttributeError(
                f"Root entity '{self.name}' does not match path '{path}'")

        if len(parts) > 1:
            if not (hasattr(self, parts[1]) and isinstance(getattr(self, parts[1]), Fuzzable)):
                raise AttributeError(
                    f"Attribute '{parts[1]}' does not exist or is not a fuzzable entity")
            return getattr(self, parts[1]).get_content_by_path(".".join(parts[1:]))
        else:
            return self

    def set_content_by_path(self, path: str, value: Any):
        """Set the value of the fuzzable entity at the specified `path`.

        Args:
            path: Path to the fuzzable entity in the structure. The path is a string consisting of 
                the names of the fuzzable entities separated by dots. For example,
                `"parent.child.grandchild"`.
            value: New value for the fuzzable entity. The value should be of the same type as the 
                fuzzable entity's data type.

        Raises:
            AttributeError: If the root entity in the path does not match the current entity's name.
        """

        parts = path.split(".")

        if parts[0] != self.name:
            raise AttributeError(
                f"Root entity '{self.name}' does not match path '{path}'")

        if len(parts) > 1:
            if hasattr(self, parts[1]) and isinstance(getattr(self, parts[1]), Fuzzable):
                getattr(self, parts[1]).set_content_by_path(
                    ".".join(parts[1:]), value)
        else:
            setattr(self, parts[0], value)

        self.is_modified = True
