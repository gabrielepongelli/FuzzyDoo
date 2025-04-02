from collections.abc import Callable, Generator
from typing import Any, Type, override

from pycrate_mobile.TS24501_FGMM import FGMMTypeClasses as mm
from pycrate_mobile.TS24501_FGSM import FGSMTypeClasses as sm
from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_mobile.TS24007 import IE
from pycrate_core.elt import Envelope, Atom, Alt
from pycrate_core.base import Buf

from fuzzydoo.proto.nas.types import UintType, map_type

from ...mutator import Fuzzable, QualifiedNameFormatError, ContentNotFoundError, Mutator, mutable
from ...utils.register import register
from ...utils.network import nas_disable_safety_checks
from ...protocol import Message, MessageParsingError
from .types import map_type, UintType, BufferType

# See TS 24.501 Annex A
# NOTE: only these are actually used by pycrate
err_msgs = {
    96: 'invalid mandatory info',
    97: 'message type non-existent or not implemented',
    111: 'unspecified protocol error',
}


@mutable
class InformationElement(Fuzzable):
    """Represents an Information Element (IE) of the NAS (Non-Access Stratum) protocol.

    This class encapsulates the structure and behavior of a NAS Information Element, providing 
    methods to access and modify its components. It supports fuzzing operations by allowing 
    controlled mutations of its content.

    An Information Element of the NAS protocol typically consists of three parts:
    1. Tag (T): Identifies the type of information element.
    2. Length (L): Specifies the length of the value field.
    3. Value (V): Contains the actual data of the information element.

    This class provides access to these components and allows for their modification, which is 
    useful for protocol fuzzing and testing.
    """

    def __init__(self, content: IE, name: str, parent: "InformationElement | NASMessage"):
        """Initialize a new `InformationElement` instance.

        Args:
            content: The `pycrate` representation of this IE.
            path: The path to the current IE within `parent`.
            parent: The parent fuzzable entity.
        """

        self._name: str = name
        self._parent: "InformationElement | NASMessage" = parent
        self._content: IE = content

        # to enable the assignment of invalid values
        nas_disable_safety_checks(self._content)

        self._leaf_paths: list[list[str]]
        if self.content is None or not isinstance(self.content, (tuple, list, dict)):
            self._leaf_paths = []
        else:
            self._leaf_paths = self._gen_leaf_paths(self.content)

        self._tag: UintType | None = self._setup_tag()
        self._length: UintType | None = self._setup_length()
        self._value: BufferType | None = self._setup_value()

    def _setup_tag(self) -> UintType | None:
        """Set up the tag component of this IE.

        Returns:
            UintType | None: A `UintType` object representing the tag if it exists, or `None` if 
                the tag component is not present in the IE.
        """

        if 'T' not in self._content.get_val_d().keys():
            return None

        return map_type(type(self._content['T']))(
            content=self._content['T'],
            path=['T'],
            parent=self
        )

    def _setup_length(self) -> UintType | None:
        """Set up the length component of this IE.

        Returns:
            UintType | None: A `UintType` object representing the length if it exists, or `None` if 
                the length component is not present in the IE.
        """

        if 'L' not in self._content.get_val_d().keys():
            return None

        return map_type(type(self._content['L']))(
            content=self._content['L'],
            path=['L'],
            parent=self
        )

    def _setup_value(self) -> BufferType | None:
        """Set up the value component of this IE.

        Returns:
            BufferType | None: A `BufferType` object representing the value if it exists, or `None` 
                if the value component is not present in the IE.
        """

        # pylint: disable=protected-access
        if self._content._V is None:
            return None

        if not isinstance(self._content._V, Buf):
            content = Buf('V', val=self._content._V.to_bytes())
            res = map_type(Buf)(
                content=content,
                path=['V'],
                parent=self
            )

            old_value_setter = res._value_setter

            def new_value_setter(new_value: BufferType | bytes):
                if isinstance(new_value, BufferType):
                    new_value: bytes = new_value.value
                if self.value is None or new_value is None:
                    return

                self._content.unset_IE()
                nas_disable_safety_checks(self._content['V'])
                self._content['V'].set_bl(len(new_value) * 8)
                self._content['V'].from_bytes(new_value)

                old_value_setter(new_value)

            res._value_setter = new_value_setter
            return res

        return map_type(type(self._content._V))(
            content=self._content._V,
            path=['V'],
            parent=self
        )

    def _gen_leaf_paths_rec(self, tree: dict | list | tuple | Any, curr: tuple = ()) -> Generator[list[str]]:
        """Recursive helper for the method `_gen_leaf_paths`.

        Args:
            tree: The nested dictionary/list/tuple/leaf structure to traverse.
            curr (optional): The current path being constructed. Defaults to an empty tuple.

        Yields:
            list[str]: A list representing the path to a leaf node in the tree structure.
        """

        if isinstance(tree, dict):
            for n, s in tree.items():
                yield from self._gen_leaf_paths_rec(s, curr + (n,))
        elif isinstance(tree, (list, tuple)):
            for idx, elem in enumerate(tree):
                yield from self._gen_leaf_paths_rec(elem, curr + (idx,))
        else:
            yield list(curr)

    def _gen_leaf_paths(self, tree: dict) -> list[list[str]]:
        """Recursively generate paths to leaf nodes in a nested tree structure.

        This function traverses a nested tree structure and returns all the paths to all leaf 
        nodes. A leaf node is any non-container (i.e. `dict`, `tuple`, `list`) value in the 
        structure.

        Args:
            tree: The nested tree structure to traverse.

        Returns:
            list[list[str]]: The list of paths to all the leaf nodes in the tree structure.
        """

        return list(self._gen_leaf_paths_rec(tree))

    @property
    def tag(self) -> UintType | None:
        """The tag field of this IE (if present)."""

        return self._tag

    @property
    def length(self) -> UintType | None:
        """The length field of this IE (if present)."""

        return self._length

    @property
    def value(self) -> BufferType | None:
        """The value field of this IE (if present)."""

        return self._value

    @property
    def content(self) -> dict | None:
        """The content of this IE."""

        # pylint: disable=protected-access
        return self._content._IE.get_val_d() if self._content._IE is not None else None

    @override
    @property
    def name(self) -> str:
        return self._name

    @property
    def bit_length(self) -> int:
        """The total bit length of this IE."""

        return self._content.get_bl()

    @override
    @property
    def parent(self) -> Fuzzable:
        return self._parent

    @override
    def get_content(self, qname: str) -> Fuzzable:
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self

        if parts[1] == 'T':
            return self.tag

        if parts[1] == 'L':
            return self.length

        if parts[1] == 'V':
            return self.value

        for path in self._leaf_paths:
            if parts[1:] == path:
                # pylint: disable=protected-access
                res: Envelope = self._content._IE if self._content._IE is not None else self._content
                for n in path:
                    res: Envelope | Atom = res[n]
                if isinstance(res, Alt):
                    res = next(i for i in res._content.values())
                return map_type(type(res))(content=res, path=path, parent=self)

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the information element")

    @override
    def set_content(self, qname: str, value: Any):
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return

        if parts[1] == 'T':
            self.tag.value = value
            return

        if parts[1] == 'L':
            self.length.value = value
            return

        if parts[1] == 'V':
            self.value.value = value
            return

        for path in self._leaf_paths:
            if parts[1:] == path:
                # pylint: disable=protected-access
                res: Envelope = self._content._IE if self._content._IE is not None else self._content
                for n in path:
                    res: Envelope | Atom = res[n]
                if isinstance(res, Alt):
                    res = next(i for i in res._content.values())
                content = map_type(type(res))(content=res, path=path, parent=self)
                content.value = value
                return
        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the information element")

    @override
    def mutators(self) -> list[tuple[Type[Mutator], str]]:
        """Get all the mutators associated with this fuzzable entity.

        This method is overridden to provide all the mutators associated with this IE, and all 
        the mutators associated with all the mutable elements contained inside this IE.

        Returns:
            list[tuple[Type[Mutator], str]]: A list of mutator classes along with the qualified 
                name of the targeted fuzzable entity.
        """

        res = []
        for path in self._leaf_paths:
            leaf = self.get_content(self.name + '.' + ".".join([str(p) for p in path]))
            res += leaf.mutators()
        res += self.tag.mutators() if self.tag is not None else []
        res += self.length.mutators() if self.length is not None else []
        res += self.value.mutators() if self.value is not None else []
        return res


@mutable
class NASMessage(Message[Envelope]):
    """Represents and manages a Non-Access Stratum (NAS) message in 5G networks.

    This class encapsulates the functionality for handling NAS messages, including parsing, 
    serialization, content manipulation, and support for fuzzing operations. It serves as a base 
    class for specific NAS message types and provides a flexible interface for working with the 
    hierarchical structure of NAS messages.
    """

    def __init__(self, subset: str, msg_type: str, content: Envelope | None = None, delay: int = 0, n_replay: int = 1, can_be_encrypted: bool = True):
        """Initialize a new `NASMessage` instance.

        Args:
            subprotocol: The name of the NAS subset to which this message belongs.
            msg_type: The name of the type of NAS message.
            content (optional): The content of the NAS message.
            delay (optional): The number of seconds to wait before sending the message. Defaults to 
                `0`.
            n_replay (optional): The number of copies of this message to send. Defaults to `1`.
            can_be_encrypted (optional): Whether the NAS message can be encrypted. Defaults to 
                `True`.
        """

        super().__init__('NAS-' + subset, msg_type + 'Message', content, delay, n_replay)

        self._msg_type: str = msg_type
        self._ies: list[InformationElement] = []
        self._can_be_encrypted: bool = can_be_encrypted
        if self._content is not None and not self.protected:
            ie: IE
            for idx, ie in enumerate(content):
                if idx == 0 or not isinstance(ie, IE):
                    continue
                self._ies.append(InformationElement(ie, ie._name, self))

    @property
    def ies(self) -> list[InformationElement]:
        """The list of Information Elements contained in this NAS message."""

        return list(self._ies)

    @property
    def spare(self) -> UintType | None:
        """The spare part of the NAS message (if present)."""

        if 'spare' not in self.content:
            return None

        s = self._content['spare']
        return map_type(type(s))(
            content=s,
            path=['spare'],
            parent=self
        )

    @spare.setter
    def spare(self, value: UintType | int | None):
        if (s := self.spare) is None:
            return

        if value is None:
            del self._content['spare']
            return

        if isinstance(value, UintType):
            value = value.value

        s.value = value

    @override
    @property
    def content(self) -> dict | None:
        return self._content.get_val_d() if self._content is not None else None

    @property
    def protected(self) -> bool:
        """Whether this message contains protected data or not."""

        return '5GMMHeaderSec' in self.content

    @override
    def parse(self, data: bytes) -> "NASMessage":
        msg, err = parse_NAS5G(data, inner=False)
        if err:
            raise MessageParsingError(f"Failed to parse NAS message with error {err}: {err_msgs[err]}")

        msg_type = msg.__class__.__name__
        if msg_type != self._msg_type \
                and (not self._can_be_encrypted or msg_type != 'FGMMSecProtNASMessage'):
            raise MessageParsingError(f"Wrong message type: '{msg_type}'")

        # pylint: disable=protected-access
        new_msg: NASMessage = self.from_name(self._protocol, self.__class__.__name__, msg)
        return new_msg

    @override
    def raw(self) -> bytes:
        return self._content.to_bytes()

    @override
    def get_content(self, qname: str) -> Fuzzable:
        parts = qname.split(".")

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self

        for ie in self.ies:
            if parts[1] == ie.name:
                return ie.get_content(".".join(parts[1:]))

        if len(parts) == 2 and parts[1] == 'spare':
            return self.spare

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

    @override
    def set_content(self, qname: str, value: Any):
        parts = qname.split(".")

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return

        for ie in self.ies:
            if parts[1] == ie.name:
                ie.set_content(".".join(parts[1:]), value)
                return

        if len(parts) == 2 and parts[1] == 'spare':
            self.spare = value

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

    @override
    def mutators(self) -> list[tuple[Type[Mutator], str]]:
        """Get all the mutators associated with this fuzzable entity.

        This method is overridden to provide all the mutators associated with this message, and all 
        the mutators associated with all the mutable elements contained inside this message.

        Returns:
            list[tuple[Type[Mutator], str]]: A list of mutator classes along with the qualified 
                name of the targeted fuzzable entity.
        """

        res = super().mutators()
        for ie in self.ies:
            res += ie.mutators()
        res += self.spare.mutators() if self.spare is not None else []
        return res


__all__ = ['NASMessage', 'InformationElement']

# dinamically create all the message classes, one for each NAS-MM message
for message_type in mm.values():
    message_type = message_type.__name__

    def _make_init_mm(msg_type: str) -> Callable[[Any, int, int], None]:
        can_be_encrypted = msg_type != 'FGMMAuthenticationRequest'

        def new_init(self, content: Envelope | None = None, delay: int = 0, n_replay: int = 1):
            NASMessage.__init__(self, 'MM', msg_type, content, delay, n_replay, can_be_encrypted)

        return new_init

    class_name = message_type + 'Message'
    class_bases = (NASMessage, )
    class_attrs = {"__init__": _make_init_mm(message_type)}
    new_class = register(Message, "NAS-MM")(mutable(type(class_name, class_bases, class_attrs)))

    globals()[class_name] = new_class
    globals()['__all__'].append(class_name)

# dinamically create all the message classes, one for each NAS-SM message
for message_type in sm.values():
    message_type = message_type.__name__

    def _make_init_sm(msg_type: str) -> Callable[[Any, int, int], None]:
        def new_init(self, content: Envelope | None = None, delay: int = 0, n_replay: int = 1):
            NASMessage.__init__(self, 'SM', msg_type, content, delay, n_replay)

        return new_init

    class_name = message_type + 'Message'
    class_bases = (NASMessage, )
    class_attrs = {"__init__": _make_init_sm(message_type)}
    new_class = register(Message, "NAS-SM")(mutable(type(class_name, class_bases, class_attrs)))

    globals()[class_name] = new_class
    globals()['__all__'].append(class_name)
