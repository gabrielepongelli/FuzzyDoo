from collections.abc import Callable
from typing import Type, Any, override, TypeVar

from pycrate_asn1rt.asnobj import ASN1Obj
import pycrate_asn1rt.asnobj_basic as basic
import pycrate_asn1rt.asnobj_str as string

from ...mutator import Fuzzable, QualifiedNameFormatError, ContentNotFoundError, mutable


class ASN1Type(Fuzzable):
    """A generic ASN.1 type.

    This class represents a generic ASN.1 type that can be fuzzed. This class provides a common 
    interface for interacting with different ASN.1 types and allows for easy fuzzing of these types.

    In practice, this class is a wrapper around the basic subtypes of ASN1Obj from the pycrate 
    package.
    """

    def __init__(self, content: ASN1Obj, path: list[str], parent):
        """Initialize an `ASN1Type` object.

        Args:
            content: The content of the ASN.1 type. This should be an instance of a class
                derived from `pycrate_asn1rt.asnobj.ASN1Obj`.
            path: The path to the current ASN.1 type within a message.
            parent: The parent fuzzable entity. It should be an instance of a class derived from 
                `NGAPMessage`
        """

        self._content: ASN1Obj = content
        self._path: list[str] = [str(p) for p in path]
        self._parent = parent

    @override
    @property
    def value(self):
        """The value represented by this ASN.1 type."""

        return self._content.get_val()

    @value.setter
    def value(self, new_value):
        if isinstance(new_value, type(self)):
            new_value = new_value.value
        self._content.set_val(new_value)

        # we need this to update the value globally, otherwise if we then convert the message to
        # raw bytes, the changes won't be reflected
        if self._parent is not None:
            qname = self._parent.name + "." + ".".join(self._path)
            self._parent.set_content(qname, self)

    @override
    @property
    def constraints(self) -> dict:
        """The constraints of this ASN.1 type."""

        return self._content.get_const()

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

        raise ContentNotFoundError(f"No content at the path \
                                    '{qname}' exists in this type")

    @override
    def set_content(self, qname: str, value: Any):
        parts = qname.split(".")

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            self.value = value
        else:
            raise ContentNotFoundError(f"No content at the path \
                                    '{qname}' exists in this type")


_MAPPING: dict[Type[ASN1Obj], Type[ASN1Type]] = {}


MappedT = TypeVar('MappedT', bound=ASN1Type)


def mapped(base: Type[ASN1Obj]) -> Callable[[MappedT], MappedT]:
    """Decorator that marks a class as wrapper of a `ASN1Obj` subtype.

    Args:
        base: The `ASN1Obj` subtype to use as key in the map.

    Example:
        >>> @mapped(pycrate_asn1rt.asnobj_basic.BOOL)
        >>> class BoolType(ASN1Type):
        >>>     pass
    """

    def decorator(cls: MappedT) -> MappedT:
        _MAPPING[base] = cls
        return cls

    return decorator


def map_type(type_to_map: Type[ASN1Obj]) -> Type[ASN1Type]:
    """Map a given ASN.1 object type to its corresponding `ASN1Type` subclass.

    Args:
        type_to_map: The type of the ASN.1 object to map.

    Returns:
        Type[ASN1Type]: The corresponding `ASN1Type` subclass for the given ASN.1 object type.

    Raises:
        KeyError: If the given ASN.1 object type is not mapped.
    """

    return _MAPPING[type_to_map]


@mutable
@mapped(basic.NULL)
class NullType(ASN1Type):
    """ASN.1 basic type NULL object.

    ASN.1 basic type NULL object. It has only one possible value, which is `int(0)`.
    """

    @override
    @property
    def fuzzable(self) -> bool:
        return False

    def mutators(self):
        return []


@mutable
@mapped(basic.BOOL)
class BoolType(ASN1Type):
    """ASN.1 basic type BOOLEAN object.

    ASN.1 basic type BOOLEAN object. Its values are of type `bool`.
    """


@mutable
@mapped(basic.INT)
class IntType(ASN1Type):
    """ASN.1 basic type INTEGER object.

    ASN.1 basic type INTEGER object. Its values are of type `int`.
    """


@mutable
@mapped(basic.REAL)
class RealType(ASN1Type):
    """ASN.1 basic type REAL object.

    ASN.1 basic type REAL object. Its values are of type `tuple[int, int, int]` with the following 
    content:
    - The 1st element represents the mantissa.
    - The 2nd element represents the base.
    - The 3rd element represents the exponent

    Special values are:
    - `(-1, None, None)` for MINUS-INFINITY.
    - `(1,  None, None)` for PLUS-INFINITY.
    - `(0,  None, None)` for NOT-A-NUMBER.
    """


@mutable
@mapped(basic.ENUM)
class EnumType(ASN1Type):
    """ASN.1 basic type ENUMERATED object.

    ASN.1 basic type ENUMERATED object. Its values are of type `str` and must correspond to one of 
    the values obtainable by calling `possible_values`.
    """

    @property
    def possible_values(self) -> list[str]:
        """The possible values for this ENUMERATED ASN.1 type.

        Returns:
            list[str]: A list of strings representing the possible values for this ENUMERATED type.
        """

        # pylint: disable=protected-access
        return list(self._content._cont_rev.values())


@mutable
@mapped(basic.OID)
class OIDType(ASN1Type):
    """ASN.1 basic type OBJECT IDENTIFIER object.

    ASN.1 basic type OBJECT IDENTIFIER object. Its values are of type `tuple[int]`.
    """


@mutable
@mapped(basic.REL_OID)
class RelOIDType(ASN1Type):
    """ASN.1 basic type RELATIVE-OID object.

    ASN.1 basic type RELATIVE-OID object. Its values are of type `tuple[int]`.
    """


class BaseStringType(ASN1Type):
    """Generic class for basic string types."""

    @property
    def codec(self) -> str:
        """The specific codec used for this string type."""

        # pylint: disable=protected-access
        return self._content._codec.replace('-', '_')


class AlphabeticalStringType(BaseStringType):
    """Generic class for string types that have a fixed alphabet."""

    @property
    def alphabet(self) -> str:
        """The specific alphabet used for this string type."""

        # pylint: disable=protected-access
        return self._content._ALPHA_RE


@mutable
@mapped(string.BIT_STR)
class BitStrType(ASN1Type):
    """ASN.1 basic type BIT STRING object.

    ASN.1 basic type BIT STRING object. Its values are of type `tuple[int, int]` with the following 
    content:
    - The 1st element represents the value as unsigned int.
    - The 2nd element represents the length in bits.
    """


@mutable
@mapped(string.OCT_STR)
class OctStrType(ASN1Type):
    """ASN.1 basic type OCTET STRING object.

    ASN.1 basic type OCTET STRING object. Its values are of type `bytes`.
    """


@mutable
@mapped(string.STR_UTF8)
class StrUtf8Type(BaseStringType):
    """ASN.1 basic type UTF8String object.

    ASN.1 basic type UTF8String object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_NUM)
class StrNumType(AlphabeticalStringType):
    """ASN.1 basic type NumericString object.

    ASN.1 basic type NumericString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_PRINT)
class StrPrintType(AlphabeticalStringType):
    """ASN.1 basic type PrintableString object.

    ASN.1 basic type PrintableString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_TELE)
class StrTeleType(BaseStringType):
    """ASN.1 basic type TeletexString object.

    ASN.1 basic type TeletexString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_T61)
class StrT61Type(BaseStringType):
    """ASN.1 basic type T61String object.

    ASN.1 basic type T61String object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_VID)
class StrVidType(BaseStringType):
    """ASN.1 basic type VideotextString object.

    ASN.1 basic type VideotextString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_IA5)
class StrIa5Type(AlphabeticalStringType):
    """ASN.1 basic type IA5String object.

    ASN.1 basic type IA5String object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_GRAPH)
class StrGraphType(BaseStringType):
    """ASN.1 basic type GraphicString object.

    ASN.1 basic type GraphicString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_VIS)
class StrVisType(AlphabeticalStringType):
    """ASN.1 basic type VisibleString object.

    ASN.1 basic type VisibleString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_ISO646)
class StrIso646Type(AlphabeticalStringType):
    """ASN.1 basic type ISO646String object.

    ASN.1 basic type ISO646String object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_GENE)
class StrGeneType(BaseStringType):
    """ASN.1 basic type GenericString object.

    ASN.1 basic type GenericString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_UNIV)
class StrUnivType(BaseStringType):
    """ASN.1 basic type UniversalString object.

    ASN.1 basic type UniversalString object. Its values are of type `str`.
    """


@mutable
@mapped(string.STR_BMP)
class StrBmpType(BaseStringType):
    """ASN.1 basic type BMPString object.

    ASN.1 basic type BMPString object. Its values are of type `str`.
    """


@mutable
@mapped(string.TIME_UTC)
class TimeUTCType(ASN1Type):
    """ASN.1 basic type UTCTime object.

    ASN.1 basic type UTCTime object. Its values are of type `tuple[str, str, str, str, str, str|None, str]`
    with the content `(YY, MM, DD, HH, MM, SS, Z)` where:
    - `SS` is optional, hence its correspondent value can be `None`.
    - `Z` corresponds to the UTC decay and can be `Z` or `{+-}HHMM`.
    """


@mutable
@mapped(string.TIME_GEN)
class TimeGenType(ASN1Type):
    """ASN.1 basic type GeneralizedTime object.

    ASN.1 basic type GeneralizedTime object. Its values are of type 
    `tuple[str, str, str, str, str|None, str|None, str|None, str]` with the content
    `(YYYY, MM, DD, HH, [MM, [SS,]] [{.,}F*,] [Z])` where:
    - `MM` and `SS` are optional, hence their correspondent values can be `None`.
    - `F*` is optional and provides a fraction of seconds, minutes or hours, hence the 5th, 6th and 
        7th element can be `None`.
    - `Z` corresponds to the UTC decay and can be `Z`, `{+-}HH` or `{+-}HHMM` and is optional, 
        hence 8th element can be `None`.
    """


__all__ = [
    "map_type",
    "ASN1Type",
    "NullType",
    "BoolType",
    "IntType",
    "RealType",
    "EnumType",
    "OIDType",
    "RelOIDType",
    "BaseStringType",
    "AlphabeticalStringType",
    "BitStrType",
    "OctStrType",
    "StrUtf8Type",
    "StrNumType",
    "StrPrintType",
    "StrTeleType",
    "StrT61Type",
    "StrVidType",
    "StrIa5Type",
    "StrGraphType",
    "StrVisType",
    "StrIso646Type",
    "StrGeneType",
    "StrUnivType",
    "StrBmpType",
    "TimeUTCType",
    "TimeGenType"
]
