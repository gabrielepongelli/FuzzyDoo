from collections.abc import Callable, Generator
from typing import Any, Type, cast, override

from pycrate_mobile.TS24501_FGMM import FGMMTypeClasses as mm
from pycrate_mobile.TS24501_FGSM import FGSMTypeClasses as sm
from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_core.elt import Envelope, Atom, Alt

from ...mutator import Fuzzable, QualifiedNameFormatError, ContentNotFoundError, Mutator, mutable
from ...utils.register import register
from ...protocol import Message, MessageParsingError
from .types import map_type, AtomicType

# See TS 24.501 Annex A
# NOTE: only these are actually used by pycrate
_err_msgs = {
    96: 'invalid mandatory info',
    97: 'message type non-existent or not implemented',
    111: 'unspecified protocol error',
}


@mutable
class NASMessage(Message):
    """Represents and manages a Non-Access Stratum (NAS) message in 5G networks.

    This class encapsulates the functionality for handling NAS messages, including parsing, 
    serialization, content manipulation, and support for fuzzing operations. It serves as a base 
    class for specific NAS message types and provides a flexible interface for working with the 
    hierarchical structure of NAS messages.
    """

    def __init__(self, subset: str, msg_type: str, content: Envelope, delay: int = 0, n_replay: int = 1):
        """Initialize a new `NASMessage` instance.

        Args:
            subprotocol: The name of the NAS subset to which this message belongs.
            msg_type: The name of the type of NAS message.
            content: The content of the NAS message.
            delay (optional): The number of seconds to wait before sending the message. Defaults to 
                `0`.
            n_replay (optional): The number of copies of this message to send. Defaults to `1`.
        """

        super().__init__('NAS-' + subset, msg_type + 'Message', content, delay, n_replay)

        self._msg_type: str = msg_type
        self._leaf_paths: list[list[str]] | None = None

    @override
    @property
    def content(self) -> dict:
        return cast(Envelope, self._content).get_val_d() if self._content is not None else {}

    def _gen_leaf_paths_rec(self, tree: dict | list | tuple | Any, curr: tuple = ()) -> Generator[list[str]]:
        """Recursive helper for the method `_gen_leaf_paths`.

        Args:
            tree: The nested dictionary/list/tuple structure to traverse. Can also be of other type 
                for leaf nodes.
            curr (optional): The current path being constructed. Defaults to an empty tuple.

        Yields:
            list[str]: A list representing the path to a leaf node in the tree structure.
        """

        if isinstance(tree, dict):
            for n, s in tree.items():
                yield from self._gen_leaf_paths_rec(s, curr + (n,))
        elif isinstance(tree, list) or isinstance(tree, tuple):
            for idx, elem in enumerate(tree):
                yield from self._gen_leaf_paths_rec(elem, curr + (idx,))
        else:
            yield list(curr)

    def _gen_leaf_paths(self, tree: dict) -> list[list[str]]:
        """Recursively generate paths to leaf nodes in a nested dictionary structure.

        This function traverses a nested dictionary structure and returns all the paths to all leaf 
        nodes. A leaf node is any non-dictionary value in the structure.

        Args:
            tree: The nested dictionary structure to traverse.

        Returns:
            list[list[str]]: The list of paths to all the leaf nodes in the tree structure.
        """

        return list(self._gen_leaf_paths_rec(tree))

    @property
    def protected(self) -> bool:
        """Check if this message contains protected data."""

        return '5GMMHeaderSec' in self.content

    @override
    def parse(self, data: bytes) -> "NASMessage":
        msg, err = parse_NAS5G(data, inner=False)
        if err:
            raise MessageParsingError(
                f"Failed to parse NAS message with error {err}: {_err_msgs[err]}")

        msg_type = msg.__class__.__name__
        if msg_type != self._msg_type and msg_type != 'FGMMSecProtNASMessage':
            raise MessageParsingError(f"Wrong message type: '{msg_type}'")

        # pylint: disable=protected-access
        new_msg: NASMessage = self.from_name(self._protocol, self.__class__.__name__)
        new_msg._content = msg
        new_msg._leaf_paths = self._gen_leaf_paths(new_msg.content)
        return new_msg

    @override
    def raw(self) -> bytes:
        return cast(Envelope, self._content).to_bytes()

    def get_content(self, qname: str) -> Fuzzable:
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return self

        for path in self._leaf_paths:
            if parts[1:] == path:
                res: Envelope = self._content
                for n in path:
                    res: Envelope | Atom = res[n]
                if isinstance(res, Alt):
                    # pylint: disable=protected-access
                    res = next(i for i in res._content.values())
                return map_type(type(res))(content=res, path=path, parent=self)

        if len(parts) == 2 and hasattr(self, str(parts[1])) and str(parts[1]) != 'content':
            return getattr(self, parts[1])

        raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

    def set_content(self, qname: str, value: Any):
        parts = [int(p) if p.isdecimal() else p for p in qname.split(".")]

        if parts[0] != self.name:
            raise QualifiedNameFormatError(
                f"Root entity '{self.name}' does not match path '{qname}'")

        if len(parts) == 1:
            return

        if parts[1:] in self._leaf_paths:
            # first try to search in the message content

            if isinstance(value, AtomicType):
                value = value.value

            res: Envelope = self._content
            for n in parts[1:]:
                res: Envelope | Atom = res[n]
            res.set_val(value)
        elif len(parts) == 2 and hasattr(self, str(parts[1])) and str(parts[1]) != 'content':
            # then try with some other attributes from the parent class
            setattr(self, parts[1], value)
        else:
            raise ContentNotFoundError(f"No content at the path '{qname}' exists in the message")

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
            leaf = self.get_content(self.name + '.' + ".".join([str(p) for p in path]))
            res += leaf.mutators()
        return res


__all__ = ['NASMessage']

# dinamically create all the message classes, one for each NAS-MM message
for message_type in mm.values():
    message_type = message_type.__name__

    def _make_init_mm(msg_type: str) -> Callable[[Any, int, int], None]:
        def new_init(self, delay: int = 0, n_replay: int = 1):
            NASMessage.__init__(self, 'MM', msg_type, delay, n_replay)

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
        def new_init(self, delay: int = 0, n_replay: int = 1):
            NASMessage.__init__(self, 'SM', msg_type, delay, n_replay)

        return new_init

    class_name = message_type + 'Message'
    class_bases = (NASMessage, )
    class_attrs = {"__init__": _make_init_sm(message_type)}
    new_class = register(Message, "NAS-SM")(mutable(type(class_name, class_bases, class_attrs)))

    globals()[class_name] = new_class
    globals()['__all__'].append(class_name)
