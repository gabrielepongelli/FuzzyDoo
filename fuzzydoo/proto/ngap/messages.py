from collections.abc import Callable
from typing import Any, Type, cast

import pycrate_asn1dir.NGAP as ngap
from pycrate_core.utils import PycrateErr
from pycrate_asn1rt.asnobj import ASN1Obj

from ...mutator import Fuzzable, QualifiedNameFormatError, ContentNotFoundError, Mutator, mutable
from ...utils.register import register
from ..message import Message, MessageParsingError
from .types import ASN1Type, EnumType, IntType, map_type


@mutable
class NGAPMessage(Message):
    """A generic NGAP message.

    This class represents a generic NGAP message and provides methods for parsing, serializing, and 
    manipulating NGAP messages. It also supports fuzzing and mutation of the message content.
    """

    def __init__(self, msg_type: str, body_type: str, content: ASN1Obj, delay: int = 0, n_replay: int = 1):
        """Initialize a new instance of `NGAPMessage`.

        Args:
            msg_type: The name of the type of NGAP message.
            body_type: The name of the type of the NGAP message's body.
            content: The content of the NGAP message.
            delay (optional): The number of seconds to wait before sending the message. Defaults to 
                `0`.
            n_replay (optional): The number of copies of this message to send. Defaults to `1`.
        """

        super().__init__("NGAP", self.__class__.__name__, content, delay, n_replay)

        self._msg_type: str = msg_type
        self._body_type: str = body_type
        self._leaf_paths: None | list[list[str]] = None

    @property
    def procedure_code(self) -> IntType:
        """The procedure code of this NGAP message."""

        return self.get_content(self.name+'.procedureCode')

    @property
    def criticality(self) -> EnumType:
        """The criticality level of this NGAP message."""

        return self.get_content(self.name+'.criticality')

    @property
    def content(self) -> Any | None:
        return self._content.get_val()

    def parse(self, data: bytes):
        ngap_pdu = ngap.NGAP_PDU_Descriptions.NGAP_PDU
        try:
            from_aper = cast(Callable[[Any], None], ngap_pdu.from_aper)
            from_aper(data)
        except PycrateErr as e:
            raise MessageParsingError(
                f"Failed to parse NGAP message: {e}") from e

        try:
            ngap_pdu.get_at([self._msg_type, 'value', self._body_type])
        except PycrateErr as e:
            pdu_content = ngap_pdu.get_val()
            raise MessageParsingError(
                f"Wrong message type: {pdu_content[0]}:{pdu_content[1]['value'][0]}") from e

        self._content = ngap_pdu
        self._leaf_paths = [path for path, _ in ngap_pdu.get_val_paths()]

    def raw(self) -> bytes:
        return self._content.to_aper()

    def _redact_path(self, path: list[str | int]) -> list[str | int]:
        """Remove elements from the specified path so that it can be used outside of this class.

        Args:
            path: Path to modify. It is assumed to be one of the paths in `self._leaf_paths`, hence 
                with their format.

        Returns:
            list[str|int]: The adapted path ready to be used outside of this class.
        """

        redacted = path[1:]  # remove msg_type
        if len(path) > 2:
            redacted = redacted[2:]  # remove also "value" and body_type
        return redacted

    def _restore_path(self, path: list[str | int]) -> list[str | int]:
        """Reconstruct the path equivalent to the specified one so that it can be used internally.

        Args:
            path: Path to reconstruct.

        Returns:
            list[str|int]: The reconstructed path ready to be used internally.
        """

        full_path = [self._msg_type]
        if len(path) > 1:
            full_path += ["value", self._body_type]
        full_path += path
        return full_path

    def get_content(self, qname: str) -> Fuzzable:
        # needed because `get_at` doesn't work with strings represening numbers
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self

        for p in self._leaf_paths:
            redacted = self._redact_path(p)
            if parts[1:] == redacted:
                res = self._content.get_at(p)
                return map_type(type(res))(content=res, path=redacted, parent=self)

        if len(parts) == 2 and hasattr(self, str(parts[1])) and str(parts[1]) != 'content':
            return getattr(self, parts[1])

        raise ContentNotFoundError(f"No content at the path \
                                    '{qname}' exists in the message")

    def set_content(self, qname: str, value: Any):
        # needed because `get_at` doesn't work with strings represening numbers
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return

        full_path = self._restore_path(parts[1:])
        if full_path in self._leaf_paths:
            # first try to search in the message content
            if isinstance(value, ASN1Type):
                value = value.value
            self._content.set_val_at(full_path, value)
        elif len(parts) == 2 and hasattr(self, str(parts[1])) and str(parts[1]) != 'content':
            # then try with some other attributes from the parent class
            setattr(self, parts[1], value)
        else:
            raise ContentNotFoundError(f"No content at the path \
                                       '{qname}' exists in the message")

    def mutators(self) -> list[tuple[Type[Mutator], str]]:
        """Get all the mutators associated with this fuzzable entity.

        This method is overridden to provide all the mutators associated with this message, and all 
        the mutators associated with all the mutable elements contained inside this message.

        Returns:
            list[tuple[Type[Mutator], str]]: A list of mutator classes along with the qualified 
                name of the targeted fuzzable entity.
        """

        res = super().mutators()
        for path in self._leaf_paths:
            redacted = [str(p) for p in self._redact_path(path)]
            leaf = self.get_content(
                self.name + '.' + ".".join(redacted))
            res += leaf.mutators()
        return res


__all__ = ['NGAPMessage']

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
            content = ngap.NGAP_PDU_Descriptions.NGAP_PDU
            msg_type = msg_type[0].lower() + msg_type[1:]

            def new_init(self, delay: int = 0, n_replay: int = 1):
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
