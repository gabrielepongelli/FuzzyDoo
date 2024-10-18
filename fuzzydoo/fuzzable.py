from abc import ABC, abstractmethod
from typing import Any, Type

from .mutator import Mutator
from .utils.errs import FuzzyDooError


class PathFormatError(FuzzyDooError):
    """Exception raised when an invalid path is found."""


class ContentNotFoundError(FuzzyDooError):
    """Exception raised when some content specified is not found."""


class Fuzzable(ABC):
    """Represent an entity that can be fuzzed, i.e., whose content (part of or all) can be mutated.

    The Fuzzable class provides a base structure for defining fuzzable entities, i.e. parts of a 
    message that can be altered during the fuzzing process.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the fuzzable entity.

        Returns:
            str: The name of the fuzzable entity.
        """

    @property
    def fuzzable(self) -> bool:
        """Check if the current fuzzable entity is fuzzable.

        Returns:
            bool: `True` if the current fuzzable entity can be fuzzed, `False` otherwise.
        """

        return True

    @property
    @abstractmethod
    def parent(self):
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
    def mutators(self) -> list[tuple[Type[Mutator], str]]:
        """Get all the mutators associated with this fuzzable entity.

        This method is intended to be overridden in subclasses to provide a list of mutator classes 
        that can be used to mutate the content of this fuzzable entity. Each mutator class should 
        be a subclass of `Mutator`.

        Returns:
            list[tuple[Type[Mutator], str]]: A list of mutator classes associated with this 
                fuzzable entity along with the qualified name of the targeted fuzzable entity.
        """

    def get_content_by_path(self, path: str):
        """Get the value of the fuzzable entity at the specified `path`.

        Args:
            path: Path to the fuzzable entity in the structure. The path is a string consisting of 
                the names of the fuzzable entities separated by dots. For example,
                `"parent.child.grandchild"`.

        Returns:
            Fuzzable: The fuzzable entity at the specified `path`.

        Raises:
            PathFormatError: If the root entity in the path does not match the current entity's 
                name. 
            ContentNotFoundError: If the path does not lead to an existing fuzzable attribute.
        """

        parts = path.split(".")

        if parts[0] != self.name:
            raise PathFormatError(
                f"Root entity '{self.name}' does not match path '{path}'")

        if len(parts) > 1:
            if not (hasattr(self, parts[1]) and isinstance(getattr(self, parts[1]), Fuzzable)):
                raise ContentNotFoundError(
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
            PathFormatError: If the root entity in the path does not match the current entity's     
                name.
            ContentNotFoundError: If the path does not lead to an existing fuzzable attribute.
        """

        parts = path.split(".")

        if parts[0] != self.name:
            raise PathFormatError(
                f"Root entity '{self.name}' does not match path '{path}'")

        if len(parts) > 2:
            if hasattr(self, parts[1]) and isinstance(getattr(self, parts[1]), Fuzzable):
                getattr(self, parts[1]).set_content_by_path(
                    ".".join(parts[1:]), value)
            else:
                raise ContentNotFoundError(
                    f"Attribute '{parts[1]}' does not exist or is not a fuzzable entity")
        else:
            setattr(self, parts[1], value)
