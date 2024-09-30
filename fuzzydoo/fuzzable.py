from abc import ABC, abstractmethod
from typing import List, Any, Type

from .mutator import Mutator


class Fuzzable(ABC):
    """Represent an entity that can be fuzzed, i.e., whose content (part of or all) can be mutated.

    The Fuzzable class provides a base structure for defining fuzzable entities, i.e. parts of a message that can be altered during the fuzzing process.

    Attributes:
        name: Name of the fuzzable entity.
        data_type: Type of the fuzzable entity.
        size: Size of the fuzzable entity in bytes.
        bit_length: Bit length of the fuzzable entity.
        is_modified (optional): Indicates whether the fuzzable entity has been modified. Defaults 
            to `False`.
        parent (optional): The parent fuzzable entity. Defaults to `None`.
    """

    def __init__(self, name: str, content: List[Type[Mutator]], data_type: type, size: int, bit_length: int, is_modified: bool = False, parent=None):
        """Initialize a Fuzzable entity.

        This constructor sets up the basic properties of a Fuzzable entity and sets up the 
        attributes of the entity based on the provided content.

        Parameters:
            name: The name of the fuzzable entity.
            content: A list of fields (attributes) of the fuzzable entity.
            data_type: The type of the fuzzable entity.
            size: The size of the fuzzable entity in bytes.
            bit_length: The bit length of the fuzzable entity.
            is_modified (optional): Indicates whether the fuzzable entity has been modified. 
                Defaults to `False`.
            parent (optional): The parent fuzzable entity. Defaults to `None`.
        """
        self.name: str = name
        self.data_type: type = data_type
        self.size: int = size
        self.bit_length: int = bit_length
        self.is_modified: bool = is_modified
        self.parent: Fuzzable | None = parent

        # set all the fields of the entity as attributes
        for field in content:
            setattr(self, field.name, field)

    @abstractmethod
    def mutators(self) -> List[Type[Mutator]]:
        """Get all the mutators associated with this fuzzable entity.

        This method is intended to be overridden in subclasses to provide a list of mutator classes 
        that can be used to mutate the content of this fuzzable entity. Each mutator class should 
        be a subclass of `Mutator`.

        Returns:
            List[Type[Mutator]]: A list of mutator classes associated with this fuzzable entity.
        """

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
        elif len(parts) > 1:
            if hasattr(self, parts[1]) and isinstance(getattr(self, parts[1]), Fuzzable):
                getattr(self, parts[1]).set_content_by_path(
                    ".".join(parts[1:]), value)
        else:
            setattr(self, parts[0], value)

        self.is_modified = True
