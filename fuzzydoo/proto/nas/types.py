from typing import override, Any, Type, TypeVar, cast
from collections.abc import Callable

from pycrate_core.elt import Atom
from pycrate_core import base

from ...mutator import Fuzzable, mutable
from ...utils.network import nas_disable_safety_checks

from ...utils.errs import *


class AtomicType(Fuzzable):
    """A wrapper class for PyCrate `Atom` types, providing a unified interface for fuzzing 
    operations.

    `AtomicType` serves as an abstraction layer over various atomic data types used in NAS messages,
    encapsulating PyCrate's `Atom` subtypes. It provides a consistent interface for accessing and
    manipulating these atomic values, while also supporting fuzzing operations.

    Note:
        This class is designed to be subclassed for specific atomic types (e.g., `UintType`, 
        `StringType`). Subclasses may provide additional type-specific functionality.
    """

    def __init__(self, content: Atom, path: list[str], parent: Fuzzable):
        """Initialize a new `AtomicType` instance.

        Args:
            content: The content of the atomic type. This should be an instance of a class derived 
                from `pycrate_core.elt.Atom`.
            path: The path to the current atomic type within `parent`.
            parent: The parent fuzzable entity.
        """

        self._path: list[str] = [str(p) for p in path]
        self._parent: Fuzzable = parent
        self._content: Atom = content

        # to enable the assignment of invalid values
        nas_disable_safety_checks(self._content)

    def _value_getter(self):
        """Function called by the property `value`."""

        return self._content.get_val()

    def _value_setter(self, new_value):
        """Function called by the property `value`."""

        if isinstance(new_value, type(self)):
            new_value = new_value.value
        self._content.set_val(new_value)

    @property
    def value(self):
        """The value represented by this atomic type."""

        return self._value_getter()

    @value.setter
    def value(self, new_value):
        self._value_setter(new_value)

    @property
    def possible_values(self) -> list:
        """The possible values for this atomic type."""

        # pylint: disable=protected-access
        if isinstance(self._content._dic, dict):
            return list(self._content._dic.keys())

        return []

    @property
    def bit_length(self) -> int:
        """The bit length of this atomic type."""

        return self._content.get_bl()

    @override
    @property
    def name(self) -> str:
        return self._path[-1]

    @override
    @property
    def parent(self) -> Fuzzable:
        return self._parent

    @override
    @property
    def qualified_name(self) -> str:
        if self.parent is None:
            return self.name

        return self.parent.qualified_name + "." + ".".join(self._path)

    @override
    def get_content(self, qname: str):
        parts = qname.split(".")

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self.value

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in this type")

    @override
    def set_content(self, qname: str, value: Any):
        parts = qname.split(".")

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            self.value = value
        else:
            raise ContentNotFoundError(f"No content at the path '{qname}' exists in this type")


_MAPPING: dict[Type[Atom], Type[AtomicType]] = {}


MappedT = TypeVar('MappedT', bound=AtomicType)


def mapped(base_cls: Type[Atom]) -> Callable[[MappedT], MappedT]:
    """Decorator that marks a class as wrapper of an `Atom` subtype.

    Args:
        base_cls: The `Atom` subtype to use as key in the map.

    Example:
        >>> @mapped(pycrate_core.base.Uint)
        >>> class UintType(AtomicType):
        >>>     pass
    """

    def decorator(cls: MappedT) -> MappedT:
        _MAPPING[base_cls] = cls
        return cls

    return decorator


def map_type(type_to_map: Type[Atom]) -> Type[AtomicType]:
    """Map a given `Atom` object type to its corresponding `AtomicType` subclass.

    Args:
        type_to_map: The type of the atomic object to map.

    Returns:
        Type[AtomicType]: The corresponding `AtomicType` subclass for the given atomic object type.

    Raises:
        KeyError: If the given atomic object type is not mapped.
    """

    try:
        return _MAPPING[type_to_map]
    except KeyError as e:
        for parent in type_to_map.__mro__:
            if parent in _MAPPING:
                return _MAPPING[parent]
        raise e


@mutable
class SequenceType(AtomicType):
    """Represents a generic sequential type for handling collections of elements."""


@mutable
@mapped(base.Buf)
class BufferType(SequenceType):
    """Represents an atomic buffer type for handling binary data.

    The `BufferType` class is a specialized subclass of `AtomicType` designed to manage binary data
    encapsulated within NAS messages. It provides a consistent interface for accessing and 
    manipulating buffer values, which are represented as `bytes`.
    """

    @override
    def _value_setter(self, new_value: "BufferType | bytes"):
        if isinstance(new_value, BufferType):
            new_value: bytes = new_value.value
        self._content.set_val(new_value)
        self._content.set_bl(len(new_value) * 8)


@mutable
@mapped(base.String)
class StringType(SequenceType):
    """Represents an atomic string type for handling textual data.

    The `StringType` class is a specialized subclass of `AtomicType` designed to manage string data
    encapsulated within NAS messages. It provides a consistent interface for accessing and 
    manipulating string values, which are represented as `str`.
    """

    @property
    def codec(self) -> str:
        """The codec used for encoding and decoding this string type."""

        return cast(base.String, self._content).CODEC

    @override
    def _value_setter(self, new_value: "StringType | str"):
        if isinstance(new_value, StringType):
            new_value: str = new_value.value
        self._content.set_val(new_value)
        self._content.set_bl(len(new_value.encode(self.codec)) * 8)


@mutable
class NumericType(AtomicType):
    """Represents a generic numeric type."""

    @override
    def _value_setter(self, new_value: "NumericType | int"):
        if isinstance(new_value, NumericType):
            new_value: int = new_value.value
        self._content.set_val(new_value)
        self._content.set_bl(new_value.bit_length())


@mutable
@mapped(base.Uint)
class UintType(NumericType):
    """Represents an atomic big-endian unsigned integer type for handling numeric data.

    The `UintType` class is a specialized subclass of `AtomicType` designed to manage unsigned 
    integer data encapsulated within NAS messages. It provides a consistent interface for accessing 
    and manipulating integer values, which are represented as `int`.
    """


@mutable
@mapped(base.Int)
class IntType(NumericType):
    """Represents an atomic big-endian signed integer type for handling numeric data.

    The `IntType` class is a specialized subclass of `AtomicType` designed to manage signed 
    integer data encapsulated within NAS messages. It provides a consistent interface for accessing 
    and manipulating integer values, which are represented as `int`.
    """


@mutable
@mapped(base.UintLE)
class UintLEType(NumericType):
    """Represents an atomic little-endian unsigned integer type for handling numeric data.

    The `UintType` class is a specialized subclass of `AtomicType` designed to manage unsigned 
    integer data encapsulated within NAS messages. It provides a consistent interface for accessing 
    and manipulating integer values, which are represented as `int`.
    """


@mutable
@mapped(base.IntLE)
class IntLEType(NumericType):
    """Represents an atomic little-endian signed integer type for handling numeric data.

    The `IntType` class is a specialized subclass of `AtomicType` designed to manage signed 
    integer data encapsulated within NAS messages. It provides a consistent interface for accessing 
    and manipulating integer values, which are represented as `int`.
    """


__all__ = [
    'map_type',
    'AtomicType',
    'SequenceType',
    'BufferType',
    'StringType',
    'NumericType',
    'UintType',
    'IntType',
    'UintLEType',
    'IntLEType'
]
