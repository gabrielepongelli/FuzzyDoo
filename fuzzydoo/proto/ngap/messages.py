from collections.abc import Callable
from typing import Any, Type, cast, override, Generic, TypeVar
from dataclasses import dataclass

import pycrate_asn1dir.NGAP as ngap
from pycrate_core.utils import PycrateErr
from pycrate_asn1rt.asnobj import ASN1Obj

from ...mutator import Fuzzable, Mutator, mutable
from ...utils.register import register
from ...utils.network import ngap_modify_safety_checks, ngap_to_aper_unsafe
from ...protocol import Message
from .types import ASN1Type, EnumType, IntType, map_type
from .aper import AperEntity

from ...utils.errs import *


Location = tuple[int, int]


AnyT = TypeVar('AnyT', bound=Any)


@dataclass
class ModifiableRawContent(Generic[AnyT]):
    """A wrapper for some raw content and its modification status."""

    content: AnyT
    """The raw content."""

    pos: Location | None
    """The position of the content in the message."""

    modified: bool = False
    """Whether the content has been modified."""


@mutable
class InformationElement(Fuzzable):
    """Represents an Information Element (IE) of the NGAP (Next Generation Application Protocol) 
    protocol.

    This class provides functionality to manipulate and interact with NGAP IEs, including methods
    to modify the IE content and its APER (Aligned Packed Encoding Rules) encoding header.

    The InformationElement class extends the Fuzzable base class, allowing it to be used in
    fuzzing operations. It encapsulates the IE's content, identifier, criticality, and provides
    methods to access and modify these attributes.
    """

    def __init__(self, content: ASN1Obj, name: str, path: list[str], parent: "InformationElement | NGAPMessage"):
        """Initialize a new instance of `InformationElement`.

        Args:
            content: The `pycrate` representation of this IE.
            name: The name of this Information Element.
            path: The path to the current IE within `parent`.
            parent: The parent fuzzable entity.
        """

        self._name: str = name
        self._parent: "InformationElement | NGAPMessage" = parent
        self._content: ASN1Obj = content
        self._sync_content()

        self._path: list[str] = [str(p) for p in path]
        self._leaf_paths = [path for path, _ in self._content.get_val_paths()]
        self._disabled_constr_paths: set[tuple] = set()

        aper = AperEntity(self._content)
        raw_ie = aper.raw()
        self._aper_ie = ModifiableRawContent[AperEntity](aper, pos=(0, len(raw_ie)))

        aper = AperEntity(self._content.get_at(['value']))
        aper_raw = aper.raw()

        # since we can modify only the preamble and/or length determinants, we modify only the
        # initial part of the content, so the offset from the end remains the same
        self._aper_content = ModifiableRawContent[AperEntity](
            aper, pos=(len(aper_raw) - raw_ie.find(aper_raw), len(aper_raw)))

    def _sync_content(self):
        """Synchronizes the internal content of this Information Element.

        This method updates the internal representation of this Information Element by extracting 
        relevant information from the ASN1Obj content.
        """

        # pylint: disable=protected-access
        val: dict
        for constr in self._content.get_at(['id'])._const_tab().root:
            try:
                if constr['Value']._tr._name == self._name:
                    val = dict(constr)
                    del val['Value']
                    del val['presence']
            except AttributeError:
                continue

        const = self._content.get_at(['value'])._get_const_tr()
        val['value'] = (self._name, const[('NGAP-IEs', self._name)].get_val())

        ngap_modify_safety_checks(self._content, [], enable=False)
        self._content.set_val(val)

    @override
    @property
    def name(self) -> str:
        return self._name

    @override
    @property
    def parent(self) -> Fuzzable:
        return self._parent

    @property
    def content(self) -> dict:
        """The content of this IE."""

        self._sync_content()
        return self._content.get_val()

    @override
    @property
    def identifier(self) -> IntType:
        """The identifier of this IE."""

        return self.get_content(self.qualified_name + '.id')

    @override
    @property
    def criticality(self) -> EnumType:
        """The criticality level of this IE."""

        return self.get_content(self.qualified_name + '.criticality')

    @property
    def ie_preamble(self) -> str:
        """The preamble of this IE in the APER encoding."""

        return self._aper_ie.content.preamble

    @ie_preamble.setter
    def ie_preamble(self, value: str) -> None:
        self._aper_ie.content.preamble = value
        self._aper_ie.modified = True
        self.set_content(self.name, self)

    @property
    def ie_content_length(self) -> int:
        """The length of the content value for this IE in the APER encoding."""

        return self._aper_content.content.length

    @ie_content_length.setter
    def ie_content_length(self, value: int) -> None:
        self._aper_content.content.length = value
        self._aper_content.modified = True
        self.set_content(self.name, self)

    @override
    @property
    def qualified_name(self) -> str:
        if self.parent is None:
            return self.name

        return ".".join([self.parent.qualified_name] + self._path + [self._name])

    def disable_constraints(self, qname: str):
        """Disables the constraints for the specified qualified name in the IE.

        Args:
            qname: The qualified name of the object for which constraints need to be disabled.

        Raises:
            QualifiedNameFormatError: If the qualified name does not follow the expected format.
            ContentNotFoundError: If the object required does not exist.
        """

        local_qname = qname[len(self.qualified_name) - len(self._name):]

        # try to see if the object required exists
        # if not, an exception is raised from get_content
        self.get_content(local_qname)

        path = [int(p) if p.isdecimal() else p for p in qname.split(".")]
        self._disabled_constr_paths.add(tuple(path[1:]))

        self._parent.disable_constraints(qname)

    def raw(self) -> bytes:
        """Return the raw content of this IE.

        Returns:
            bytes: The raw content of the IE.
        """

        raw_data: bytes
        if self._aper_ie.modified:
            raw_data = self._aper_ie.content.raw()
        else:
            self._sync_content()
            raw_data = ngap_to_aper_unsafe(self._content, self._disabled_constr_paths)

        if self._aper_content.modified:
            pos, size = self._aper_content.pos
            raw_data = raw_data[:-pos] + self._aper_content.content.raw() + raw_data[-pos + size:]

        return raw_data

    @override
    def get_content(self, qname: str) -> Fuzzable:
        # needed because `get_at` doesn't work with strings represening numbers
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self

        for p in self._leaf_paths:
            if parts[1:] == p:
                self._sync_content()
                ngap_modify_safety_checks(self._content, p, enable=False)
                res = self._content.get_at(p)
                return map_type(type(res))(content=res, path=p, parent=self)

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

    @override
    def set_content(self, qname: str, value: Any):
        # needed because `get_at` doesn't work with strings represening numbers
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            if self._parent is not None:
                self._parent.set_content(self.qualified_name, value)
            return

        path = parts[1:]
        if path in self._leaf_paths:
            qname = ".".join([self._parent.name] + self._path + [qname])
            self._parent.set_content(qname, value)
            return

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

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
            path = ".".join([str(p) for p in path])
            leaf = self.get_content(self.name + "." + path)
            res += leaf.mutators()
        return res


@mutable
class NGAPMessage(Message[ASN1Obj]):
    """Represents a generic NGAP (Next Generation Application Protocol) message.

    This class provides a comprehensive representation of NGAP messages, offering methods for 
    parsing, serializing, modifying, and manipulating both the message content and its constituent 
    Information Elements (IEs). It also supports modification of certain APER (Aligned Packed 
    Encoding Rules) header information.
    """

    def __init__(self, msg_type: str, body_type: str, content: ASN1Obj | None = None, delay: int = 0, n_replay: int = 1):
        """Initialize a new instance of `NGAPMessage`.

        Args:
            msg_type: The name of the type of NGAP message.
            body_type: The name of the type of the NGAP message's body.
            content (optional): The content of the NGAP message. Defaults to `None`.
            delay (optional): The number of seconds to wait before sending the message. Defaults to
                `0`.
            n_replay (optional): The number of copies of this message to send. Defaults to `1`.
        """

        super().__init__("NGAP", self.__class__.__name__, content, delay, n_replay)

        self._msg_type: str = msg_type
        self._body_type: str = body_type

        self._disabled_constr_paths: set[tuple] = set()

        self._aper_msg: ModifiableRawContent[AperEntity] | None = None
        self._aper_content: ModifiableRawContent[AperEntity] | None = None
        self._aper_ies: ModifiableRawContent[AperEntity] | None = None
        self._ies: list[ModifiableRawContent[InformationElement]] | None = None

        if content is not None:
            aper = AperEntity(content)
            raw_msg = aper.raw()
            self._aper_msg = ModifiableRawContent[AperEntity](aper, pos=(0, len(raw_msg)))

            aper = AperEntity(content.get_at([self._msg_type, 'value']))
            aper_raw = aper.raw()

            # since we can modify only the preamble and/or length determinants, we modify only the
            # initial part of the content, so the offset from the end remains the same
            self._aper_content = ModifiableRawContent[AperEntity](
                aper, pos=(len(aper_raw) - raw_msg.find(aper_raw), len(aper_raw)))

            ies = content.get_at([self._msg_type, 'value', self._body_type, 'protocolIEs'])
            aper = AperEntity(ies)
            aper_raw = aper.raw()
            self._aper_ies = ModifiableRawContent[AperEntity](
                aper, pos=(len(aper_raw) - raw_msg.find(aper_raw), len(aper_raw)))

            self._ies = []
            generic_ie = content.get_at([self._msg_type, 'value', self._body_type, 'protocolIEs', 0])
            for idx, val in enumerate(self.content[1]['value'][1]['protocolIEs']):

                name = val['value'][0]
                ie = InformationElement(generic_ie, name, path=['ies', idx], parent=self)
                ies._cont.set_val(ies.get_val_at([0]))
                raw = ies.get_at([idx]).to_aper()
                pos = (len(raw) - raw_msg.find(raw), len(raw))
                self._ies.append(ModifiableRawContent[InformationElement](ie, pos=pos))

    @property
    def procedure_code(self) -> IntType | None:
        """The procedure code of this NGAP message."""

        if self.initialized:
            return self.get_content(self.qualified_name + '.procedure_code')
        return None

    @property
    def criticality(self) -> EnumType | None:
        """The criticality level of this NGAP message."""

        if self.initialized:
            return self.get_content(self.qualified_name + '.criticality')
        return None

    @property
    def message_type_preamble(self) -> str | None:
        """The preamble of the message type in the APER encoding."""

        if self.initialized:
            return self._aper_msg.content.preamble
        return None

    @message_type_preamble.setter
    def message_type_preamble(self, value: str) -> None:
        if self.initialized:
            self._aper_msg.content.preamble = value
            self._aper_msg.modified = True

    @property
    def message_value_length(self) -> int | None:
        """The length of the message value in the APER encoding."""

        if self.initialized:
            return self._aper_content.content.length
        return None

    @message_value_length.setter
    def message_value_length(self, value: int) -> None:
        if self.initialized:
            self._aper_content.content.length = value
            self._aper_content.modified = True

    @property
    def n_ies(self) -> int | None:
        """The number of IEs according to the APER encoding."""

        if self.initialized:
            return self._aper_ies.content.length
        return None

    @n_ies.setter
    def n_ies(self, value: int) -> None:
        if self.initialized:
            self._aper_ies.content.length = value
            self._aper_ies.modified = True

    @override
    @property
    def content(self) -> Any | None:
        if self.initialized:
            return self._content.get_val()
        return None

    @property
    def ies(self) -> list[InformationElement]:
        """The list of information elements contained in this NGAP message."""

        return list(map(lambda ie: ie.content, self._ies))

    def _qname_to_path(self, qname: str) -> list[str | int]:
        """Reconstruct the path equivalent to the specified qualified name so that it can be used 
        internally with pycrate objects.

        Args:
            qname: Qualified name to reconstruct.

        Returns:
            list[str|int]: The reconstructed path ready to be used internally.

        Raises:
            QualifiedNameFormatError: If the qualified name does not follow the expected format.
            ContentNotFoundError: If the object required does not exist.
        """

        # try to see if the object required exists
        # if not, an exception is raised from get_content
        self.get_content(qname)

        path = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        res = [self._msg_type]
        if len(path) == 1:
            return res

        if path[1] == 'procedure_code':
            res.append('procedureCode')
        elif path[1] == 'criticality':
            res.append('criticality')
        else:
            res.extend(['value', self._body_type, 'protocolIEs'])

        if len(path) == 2:
            return res

        res.append(path[2])
        res.extend(path[4:])
        return res

    def disable_constraints(self, qname: str):
        """Disables the constraints for the specified qualified name in the NGAP message.

        Args:
            qname: The qualified name of the object for which constraints need to be disabled.

        Raises:
            QualifiedNameFormatError: If the qualified name does not follow the expected format.
            ContentNotFoundError: If the object required does not exist.
        """

        self._disabled_constr_paths.add(tuple(self._qname_to_path(qname)))

    @override
    def parse(self, data: bytes) -> "NGAPMessage":
        ngap_pdu: ASN1Obj = ngap.NGAP_PDU_Descriptions.NGAP_PDU
        try:
            from_aper = cast(Callable[[Any], None], ngap_pdu.from_aper)
            from_aper(data)
        except PycrateErr as e:
            raise MessageParsingError(f"Failed to parse NGAP message: {e}") from e

        try:
            ngap_pdu.get_val_at([self._msg_type, 'value', self._body_type])
        except PycrateErr as e:
            pdu_content = ngap_pdu.get_val()
            raise MessageParsingError(
                f"Wrong message type: {pdu_content[0]}:{pdu_content[1]['value'][0]}") from e

        new_msg: NGAPMessage = self.from_name(
            self._protocol, self.__class__.__name__, content=ngap_pdu)
        return new_msg

    @override
    def raw(self) -> bytes:
        if not self.initialized:
            return b""

        raw_data: bytes
        if self._aper_msg.modified:
            raw_data = self._aper_msg.content.raw()
        else:
            raw_data = ngap_to_aper_unsafe(self._content, self._disabled_constr_paths)

        if self._aper_content.modified:
            pos, size = self._aper_content.pos
            raw_data = raw_data[:-pos] + self._aper_content.content.raw() + raw_data[-pos + size:]

        if self._aper_ies.modified:
            pos, size = self._aper_ies.pos
            raw_data = raw_data[:-pos] + self._aper_ies.content.raw() + raw_data[-pos + size:]

        for ie in self._ies:
            if not ie.modified:
                continue

            if ie.pos is None:
                raw_data += ie.content.raw()
            else:
                pos, size = ie.pos
                raw_data = raw_data[:-pos] + ie.content.raw() + raw_data[-pos + size:]

        return raw_data

    @override
    def get_content(self, qname: str) -> Fuzzable:
        # needed because `get_at` doesn't work with strings represening numbers
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self

        if self.initialized:
            if len(parts) == 2:
                if parts[1] == 'procedure_code':
                    path = [self._msg_type, 'procedureCode']
                    res = self._content.get_at(path)
                    ngap_modify_safety_checks(self._content, path, enable=False)
                    return map_type(type(res))(content=res, path=['procedure_code'], parent=self)

                if parts[1] == 'criticality':
                    path = [self._msg_type, 'criticality']
                    res = self._content.get_at(path)
                    ngap_modify_safety_checks(self._content, path, enable=False)
                    return map_type(type(res))(content=res, path=['criticality'], parent=self)

            if parts[1] == 'ies' and 0 <= parts[2] < len(self._ies):
                ie: InformationElement = self._ies[parts[2]].content
                if len(parts) == 3:
                    return ie
                return ie.get_content(".".join([str(p) for p in parts[3:]]))

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

    @override
    def set_content(self, qname: str, value: Any):
        # needed because `get_at` doesn't work with strings represening numbers
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return

        if self.initialized:
            if isinstance(value, ASN1Type):
                value = value.value

            full_path = [self._msg_type]
            if len(parts) == 2:
                if parts[1] == 'procedure_code':
                    full_path.append('procedureCode')
                    ngap_modify_safety_checks(self._content, full_path, enable=False)
                    self._content.set_val_at(full_path, value)
                    return

                if parts[1] == 'criticality':
                    full_path.append('criticality')
                    ngap_modify_safety_checks(self._content, full_path, enable=False)
                    self._content.set_val_at(full_path, value)
                    return

            full_path.extend(['value', self._body_type, 'protocolIEs'])
            if parts[1] == 'ies':
                full_path.append(parts[2])
                if 0 <= parts[2] < len(self._ies):
                    ie: ModifiableRawContent[InformationElement] = self._ies[parts[2]]
                    if 3 <= len(parts) <= 4 and isinstance(value, InformationElement):
                        # update the whole IE
                        ie.content = value
                        ie.modified = True
                        return

                    # update some specific field of an IE
                    full_path.extend(parts[4:])
                    if isinstance(value, ASN1Type):
                        value = value.value
                    ngap_modify_safety_checks(self._content, full_path, enable=False)
                    self._content.set_val_at(full_path, value)
                    return

                if parts[2] == len(self._ies) and isinstance(value, InformationElement):
                    # a new IE is added at the end
                    self._ies.append(ModifiableRawContent[InformationElement](
                        value, pos=None, modified=True))
                    return

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
        if self.initialized:
            res += self.procedure_code.mutators()
            res += self.criticality.mutators()
            for ie in self._ies:
                res += ie.content.mutators()
        return res


__all__ = ['NGAPMessage', 'InformationElement']

# dinamically create all the message classes, one for each NGAP message

# pylint: disable=protected-access no-member
for message_type in ngap.NGAP_PDU_Descriptions.NGAP_PDU._cont_tags.values():
    message_type: str = message_type[0].capitalize() + message_type[1:]
    pdu = getattr(ngap.NGAP_PDU_Descriptions, message_type)
    body_types = pdu.get_at(['value']).get_const()['tab'].get_val().root

    def get_pred(msg_type: str):
        def pred(item: dict):
            if msg_type not in item:
                return (None, None)
            ref = item[msg_type].get_typeref()
            return (ref._name, ref)
        return pred

    filtered_bodies = map(get_pred(message_type), body_types)
    for k, v in filtered_bodies:
        if k is None:
            continue

        def make_init(msg_type: str, body_type: str) -> Callable[[Any, int, int], None]:
            msg_type = msg_type[0].lower() + msg_type[1:]

            def new_init(self, content: ASN1Obj | None = None, delay: int = 0, n_replay: int = 1):
                NGAPMessage.__init__(self, msg_type, body_type, content, delay,
                                     n_replay)

            return new_init

        class_name = k + 'Message'
        class_bases = (NGAPMessage, )
        class_attrs = {"__init__": make_init(message_type, k)}
        new_class = register(Message, "NGAP")(
            mutable(type(class_name, class_bases, class_attrs)))

        globals()[class_name] = new_class
        globals()['__all__'].append(class_name)
