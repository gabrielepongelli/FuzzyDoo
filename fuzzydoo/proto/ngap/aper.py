from math import ceil
from itertools import zip_longest
from typing import ClassVar

from bitarray import bitarray
from bitarray.util import int2ba, ba2int
from pycrate_asn1rt.asnobj import ASN1Obj
from pycrate_asn1rt.asnobj_construct import CHOICE, SEQ, SET, SEQ_OF, SET_OF
from pycrate_asn1rt.asnobj_basic import INT, ENUM
from pycrate_asn1rt.asnobj_str import BIT_STR, OCT_STR, _String as GENERIC_STR
from pycrate_asn1rt.asnobj_ext import OPEN
from pycrate_asn1rt.setobj import ASN1Set
from pycrate_core.utils_py3 import pack_val, TYPE_UINT, TYPE_BYTES

from ...utils.network import PYCRATE_NGAP_STRUCT_LOCK


class AperEntity:
    """A class representing an ASN.1 Aligned Packed Encoding Rules (APER) encoded entity.

    APER is a set of encoding rules for ASN.1 data structures that provides a compact representation
    while maintaining byte alignment. The main structure of an APER record typically consists of:
    1. Preamble: Contains flags and metadata about the encoded data.
    2. Length Determinants: Indicate the size of the encoded data or its fragments.
    3. Content: The actual encoded data, potentially split into fragments.

    This class provides functionality to encode and manage ASN.1 objects according to the APER 
    specification. It manages the encoding process, including generating preambles for extended 
    types, computing and storing length determinants, and computing data fragments.
    """

    DETERMINANT_SIZES: ClassVar[tuple[int, int, int, int]] = (16384, 32768, 49152, 65536)
    """Tuple of standard fragment sizes for length encoding."""

    fragments: list[bytes]
    """The list of fragments of data contained in this entity."""

    def __init__(self, entity: ASN1Obj):
        """Initialize an `AperEntity` instance.

        Args:
            entity: The ASN.1 object to be parsed.
        """

        with PYCRATE_NGAP_STRUCT_LOCK:
            self._preamble: bitarray = self._get_preamble(entity)
            self._size: int = self._get_content_size(entity)
            self._length_unit: str = self._get_length_unit(entity)
            self._len_dets: list[bitarray] = self._get_len_dets(entity, self._size)

            self.fragments: list[bytes] = self._get_fragments(entity)

    def _size_to_index(self, size: int) -> int:
        """Map a standard fragment size to its respective index for encoding purposes.

        Args:
            size: The size value to be converted to an index. Must be one of the values in the 
                `DETERMINANT_SIZES` tuple.

        Returns:
            int: The index of the given size in the `DETERMINANT_SIZES` tuple incremented by 1.
        """

        assert size in self.DETERMINANT_SIZES
        return self.DETERMINANT_SIZES.index(size) + 1

    def _index_to_size(self, idx: int) -> int:
        """Map an index obtained with `_size_to_index` to its respective size for decoding purposes.

        Args:
            idx: The index value to be converted to a size.

        Returns:
            int: The size that corresponds to the index specified.
        """

        assert idx < 0 <= len(self.DETERMINANT_SIZES)
        return self.DETERMINANT_SIZES[idx - 1]

    def _compute_small_len_det(self, size: int) -> bitarray:
        """Compute a small length determinant for APER encoding.

        Args:
            size: The size value to encode as a length determinant.

        Returns:
            bitarray: The encoded length determinant as a bitarray.
                - For 0 <= size <= 127: 8-bit encoding.
                - For 128 <= size <= 16383: 16-bit encoding with first bit set.
                - For size in `DETERMINANT_SIZES`: 8-bit encoding with first two bits set.
                - For other sizes: empty bitarray
        """

        if 0 <= size <= 127:
            return int2ba(size, 8, endian='big')

        if 128 <= size < self.DETERMINANT_SIZES[0]:
            res = int2ba(size, 16, endian='big')
            res[0] = 1
            return res

        if size in self.DETERMINANT_SIZES:
            res = int2ba(self._size_to_index(size), 8, endian='big')
            res[0:2] = 1
            return res

        return bitarray()

    def _get_fragment_sizes(self, size: int) -> tuple[list[tuple[int, int]], int]:
        """Calculate the fragment sizes and their counts for a given size.

        This function determines how a given size can be broken down into standard fragment sizes 
        and returns the number of each fragment size needed, along with any remaining size.

        Args:
            size: The total size to be fragmented.

        Returns:
            tuple: A tuple containing:
                - A list of tuples, where each tuple consists of a fragment size and the number of 
                  times that fragment size is used.
                - An integer representing the remaining size after fragmentation.
        """

        fragments: list[tuple[int, int]] = []
        for s in reversed(self.DETERMINANT_SIZES):
            fragments.append((s, size // s))
            size -= s * fragments[-1][1]

        return fragments, size

    def _compute_len_dets(self, size: int) -> list[bitarray]:
        """Compute the length determinants for a given size in APER encoding.

        This function calculates the necessary length determinants for encoding a given size
        according to the Aligned Packed Encoding Rules (APER). It handles both small sizes that
        do not require fragmentation and larger sizes that need to be broken down into standard
        fragment sizes.

        Args:
            size: The total size to be encoded as length determinants.

        Returns:
            list[bitarray]: A list of bitarrays, each representing a length determinant for a
                fragment of the given size.
        """

        if size < self.DETERMINANT_SIZES[0]:
            # do not require fragmentation
            return [self._compute_small_len_det(size)]

        fragments, reminder = self._get_fragment_sizes(size)
        res = []
        # encode all fragments
        for (frag_size, frag_number) in fragments:
            # going from the largest fragments (64k) to the shortest ones (16k)
            for _ in range(frag_number):
                res.append(self._compute_small_len_det(frag_size))

        res.append(self._compute_small_len_det(reminder))
        return res

    def _encode_pad(self, size: int) -> bitarray:
        """Calculate the padding required to align a bitarray to the next byte boundary.

        Args:
            size: The bits of the bitarray that follow the last aligned byte.

        Returns:
            bitarray: The necessary padding bits to reach the next byte boundary.
        """

        return bitarray(8 - size)

    def _encode_len(self, val: int, constraint: ASN1Set, prev: bitarray | None = None) -> bitarray:
        """Encode a length value according to the specified ASN.1 constraints.

        Args:
            val: The length value to be encoded.
            constraint: The ASN.1 constraint that defines the encoding rules.
            prev (optional): A bitarray to append the encoded length to. If not provided, a new 
                bitarray is created.

        Returns:
            bitarray: The encoded length adjusted according to the specified constraints.
        """

        res = prev if prev is not None else bitarray()
        val = val - constraint.lb
        if constraint.ra <= 255:
            # no realignment
            bl = constraint.rdyn
        elif constraint.ra <= 65536:
            # 1 or 2 bytes encoding
            if pad_len := len(res) % 8:
                res.extend(self._encode_pad(pad_len))
            if constraint.ra == 256:
                bl = 8
            else:
                bl = 16
        else:
            # custom length determinant
            odyn = int(ceil(constraint.rdyn / 8.0)) - 1
            ldet_bl = odyn.bit_length()
            if val:
                val_dyn = int(ceil(val.bit_length() / 8.0))
            else:
                val_dyn = 1
            res = int2ba(val_dyn - 1, ldet_bl, endian='big')
            bl = 8 * val_dyn
            if pad_len := len(res) % 8:
                res.extend(self._encode_pad(pad_len))
        res.extend(int2ba(val, bl, endian='big'))
        return res

    def _get_preamble(self, entity: ASN1Obj) -> bitarray:
        """Generate the preamble for the APER encoding.

        This method generates the preamble that is required for APER encoding, which may involve
        encoding initial flags, types, or other metadata to indicate the structure of the encoded 
        data.

        Args:
            entity: The ASN.1 entity whose preamble is to be generated.

        Returns:
            bitarray: The preamble generated.
        """

        # pylint: disable=protected-access
        if isinstance(entity, INT):
            if entity._const_val and entity._const_val.ext is not None:
                if not entity._const_val.in_root(entity.get_val()):
                    return int2ba(1, 1, endian='big')
                return int2ba(0, 1, endian='big')

        if isinstance(entity, (OCT_STR, GENERIC_STR)):
            if isinstance(entity, GENERIC_STR):
                if entity._get_char_dyn() is None:
                    length = len(entity.get_val().encode(entity._codec))
                else:
                    # ldet is the length in number of chars, each encoded in `char_len` bits
                    length = len(entity.get_val())
            else:
                length = len(entity.get_val())
            if entity._const_sz and entity._const_sz._ev is not None:
                if not entity._const_sz.in_root(length):
                    return int2ba(1, 1, endian='big')
                return int2ba(0, 1, endian='big')

        if isinstance(entity, (CHOICE, ENUM)):
            if isinstance(entity, CHOICE):
                val = entity.get_val()[0]
            else:
                val = entity.get_val()
            if entity._ext is not None:
                if val in entity._root:
                    res = int2ba(0, 1, endian='big')
                    if not isinstance(entity, CHOICE):
                        return res
                    idx = entity._root.index(val)
                else:
                    res = int2ba(1, 1, endian='big')
                    if val in entity._ext:
                        idx = entity._ext.index(val)
                    else:
                        idx = int(val[5:])

                    if idx < 64:
                        res.extend(int2ba(idx, 7, endian='big'))
                    else:
                        res.append(1)
                    return res
            else:
                idx = entity._root.index(val)
                res = bitarray()

            if len(entity._root) > 1:
                res = self._encode_len(idx, entity._const_ind, prev=res)
            return res

        if isinstance(entity, (SEQ, SET)):
            res = bitarray()
            if entity._ext is not None:
                # check if some extended components are provided
                for k in entity.get_val():
                    if k in entity._ext or k[:5] == '_ext_':
                        res = int2ba(1, 1, endian='big')
                        break
                else:
                    res = int2ba(0, 1, endian='big')
            if entity._root_opt:
                opt = bitarray(len(entity._root_opt))
                val = entity.get_val()
                for i in range(len(opt)):
                    ident = entity._root_opt[i]
                    if ident in val:
                        if val[ident] == entity._cont[ident]._def:
                            # the value provided equals the default one
                            # hence will not be encoded
                            del val[ident]
                        else:
                            # component present in the encoding
                            opt[-1 - i] = 1
                # encoding the bitmap value
                res.extend(opt)
            return res

        if isinstance(entity, (SEQ_OF, SET_OF)):
            if entity._const_sz and entity._const_sz.ext is not None:
                if not entity._const_sz.in_root(len(entity.get_val())):
                    return int2ba(1, 1, endian='big')
                return int2ba(0, 1, endian='big')

        if isinstance(entity, OPEN):
            content_name: str = entity.get_val()[0]
            return self._get_preamble(entity._get_val_obj(content_name))

        return bitarray()

    def _get_content_size(self, entity: ASN1Obj) -> int:
        """Determine the size of the content to be encoded.

        This method calculates the size of the content that needs to be encoded based on the type
        of ASN.1 object and its constraints.

        Args:
            entity: The ASN.1 entity whose content size is to be determined.

        Returns:
            int: The size of the content to be encoded.
        """

        # pylint: disable=protected-access
        if isinstance(entity, OPEN):
            content_name: str = entity.get_val()[0]
            return self._get_content_size(entity._get_val_obj(content_name))

        if not isinstance(entity, (INT, BIT_STR, OCT_STR, GENERIC_STR, SEQ_OF, SET_OF)):
            return 0

        if isinstance(entity, INT):
            if entity._const_val is None:
                return 0
            return len(entity.get_val().to_bytes())

        length: int
        if isinstance(entity, BIT_STR):
            _, length = entity.get_val()
        elif isinstance(entity, OCT_STR):
            length = len(entity.get_val())
        elif isinstance(entity, (SEQ_OF, SET_OF)):
            length = len(entity.get_val())
        else:
            char_len = entity._get_char_dyn()
            if char_len is None:
                val = entity.get_val().encode(entity._codec)
                length = len(val)
            else:
                # ldet is the length in number of chars, each encoded in `char_len` bits
                length = len(entity.get_val())
                if char_len < entity._clen:
                    # alphabet constraint: character remapping required
                    val = [entity._const_alpha.root.index(c) for c in entity.get_val()]
                elif char_len == 4:
                    # numeric string
                    val = [entity._ALPHA_RE.find(c) for c in entity.get_val()]
                elif char_len == 7:
                    # ascii encoding in UPER
                    val = list(map(ord, entity.get_val()))
                else:
                    # ascii encoding in APER, utf-8, utf-16 or utf-32
                    val = entity.get_val().encode(entity._codec)

            if length >= 16384 and char_len is not None:
                length = len(val)

        return length

    def _get_length_unit(self, entity: ASN1Obj) -> str:
        """Get the unit of measurement for the length of the encoded entity.

        This method determines the unit used to measure the length of the encoded content. The unit
        could be `bits`, `bytes`, `elements`, or `chars`, depending on the type of the ASN.1 object.

        Args:
            entity: The ASN.1 entity whose length unit is to be determined.

        Returns:
            str: The unit of measurement for the length.
        """

        # pylint: disable=protected-access
        if isinstance(entity, OPEN):
            content_name: str = entity.get_val()[0]
            return self._get_length_unit(entity._get_val_obj(content_name))

        if not isinstance(entity, (INT, BIT_STR, OCT_STR, GENERIC_STR, SEQ_OF, SET_OF)):
            return ""

        if isinstance(entity, INT):
            if entity._const_val is None:
                return ""
            return 'bytes'

        unit: str
        if isinstance(entity, BIT_STR):
            unit = 'bits'
        elif isinstance(entity, OCT_STR):
            unit = 'bytes'
        elif isinstance(entity, (SEQ_OF, SET_OF)):
            unit = 'elements'
        else:
            char_len = entity._get_char_dyn()
            if char_len is None:
                unit = 'bytes'
            else:
                unit = 'chars'

        return unit

    def _get_len_dets(self, entity: ASN1Obj, length: int) -> list[bitarray]:
        """Retrieve the length determinants for the encoded data.

        This method computes and returns the length determinants that indicate the size of each
        fragment in the APER encoding. The length determinants are used to inform the decoder of the
        length of each fragment.

        Args:
            entity: The ASN.1 entity whose length determinants are to be computed.
            length: The total length of the data for which the length determinants will be computed.

        Returns:
            list[bitarray]: The length determinants for each fragment.
        """

        # pylint: disable=protected-access
        if isinstance(entity, OPEN):
            content_name: str = entity.get_val()[0]
            return self._get_len_dets(entity._get_val_obj(content_name), length)

        if not isinstance(entity, (INT, BIT_STR, OCT_STR, GENERIC_STR, SEQ_OF, SET_OF)):
            return []

        if isinstance(entity, INT):
            if entity._const_val is None:
                return []
            return self._compute_len_dets(length)

        if entity._const_sz:
            if entity._const_sz._ev is not None:
                if not entity._const_sz.in_root(length):
                    # 1) size in the extension part
                    # encoded as unconstraint integer
                    return self._compute_len_dets(length)
            # size in the root part
            if entity._const_sz.rdyn:
                # 2) defined range of possible sizes
                if entity._const_sz.ub >= 65536:
                    return self._compute_len_dets(length)
                return [self._encode_len(length, entity._const_sz)]
            elif entity._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if entity._const_sz.ub >= 65536:
                    return self._compute_len_dets(length)
                return []
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        return self._compute_len_dets(length)

    def _get_fragments(self, entity: ASN1Obj) -> list[bytes]:
        """Retrieve the fragments of data for the encoded entity.

        This method splits the encoded entity into fragments of appropriate sizes based on the APER
        encoding rules.

        Args:
            entity: The ASN.1 entity whose fragments are to be retrieved.

        Returns:
            list[bytes]: The encoded data fragments.
        """

        # pylint: disable=protected-access
        if isinstance(entity, OPEN):
            content_name: str = entity.get_val()[0]
            return self._get_fragments(entity._get_val_obj(content_name))

        if isinstance(entity, (SET_OF, SEQ_OF)):
            ldet_gen = (ldet for ldet in self._len_dets)
            ldet = next(ldet_gen)
            encoded = ldet[0] == 1 and ldet[1] == 1
            if encoded:
                ldet = ldet[2:]
            elif ldet[0] == 1:
                ldet = ldet[1:]
            count = ba2int(ldet)
            if encoded:
                count = self._index_to_size(count)
            res: list[bytes] = []
            fragment = b""
            for i in range(self._size):
                entity._cont.set_val(entity.get_val()[i])
                fragment += entity._cont.to_aper()
                count -= 1
                if count == 0:
                    res.append(fragment)
                    fragment = b""
                    try:
                        ldet = next(ldet_gen)
                    except StopIteration:
                        break
                    encoded = ldet[0] == 1 and ldet[1] == 1
                    if encoded:
                        ldet = ldet[2:]
                    elif ldet[0] == 1:
                        ldet = ldet[1:]
                    count = ba2int(ldet)
                    if encoded:
                        count = self._index_to_size(count)
            return res

        if isinstance(entity, GENERIC_STR):
            char_len = entity._get_char_dyn()
            if char_len is None:
                buf = entity.get_val().encode(entity._codec)
                length = len(buf)
            else:
                length = len(entity.get_val())
                if char_len < entity._clen:
                    # alphabet constraint: character remapping required
                    buf = [entity._const_alpha.root.index(c) for c in entity.get_val()]
                elif char_len == 4:
                    # numeric string
                    buf = [entity._ALPHA_RE.find(c) for c in entity.get_val()]
                elif char_len == 7:
                    # ascii encoding in UPER
                    buf = list(map(ord, entity.get_val()))
                else:
                    # ascii encoding in APER, utf-8, utf-16 or utf-32
                    buf = entity.get_val().encode(entity._codec)

            if entity._const_sz \
                    and (entity._const_sz.rdyn or entity._const_sz.rdyn == 0) \
                    and entity._const_sz.ub < self.DETERMINANT_SIZES[-1] \
                    or length < self.DETERMINANT_SIZES[0]:
                if char_len is None or isinstance(buf, bytes):
                    # use bytes for storing the content
                    return [buf]
                return pack_val(*[(TYPE_UINT, v, char_len) for v in buf])[0]

            # size is semi-constrained or unconstrained and requires fragmentation
            frags, reminder = self._get_fragment_sizes(len(buf))
            res: list[bytes] = []
            is_bytes = isinstance(buf, bytes) or char_len is None
            char_len = 8 if is_bytes else char_len
            off = 0
            frags.append((reminder, 1))
            for (fs, fn) in frags:
                # going from the largest fragments (64k) to the shortest ones (16k)
                # fs: frag sz, fn: frag number
                if not fn:
                    continue

                to_pack = []
                for i in range(fn):
                    if is_bytes:
                        bl = fs * char_len
                        ol = bl >> 3
                        to_pack.append((TYPE_BYTES, buf[off:off + ol], bl))
                        off += ol
                    else:
                        to_pack.extend([(TYPE_UINT, v, char_len) for v in buf[off:off + fs]])
                        off += fs

                res.append(pack_val(*to_pack))

            return res

        if isinstance(entity, (INT, BIT_STR, OCT_STR)):
            raw: bytes
            if bit_str := isinstance(entity, BIT_STR):
                value: tuple = entity.get_val()
                if not isinstance(value[0], int):
                    # value is for a contained object to be encoded
                    cont: ASN1Obj = entity._get_val_obj(value[0])
                    cont.set_val(value[1])
                    raw = cont.to_aper()
                else:
                    # value is the standard (uint, bit length)
                    if value[1]:
                        raw = value[0].to_bytes(ceil(value[1] / 8))
                    else:
                        # empty bit string
                        raw = b""
            elif isinstance(entity, OCT_STR):
                value: bytes | tuple = entity.get_val()
                if not isinstance(value, bytes):
                    cont = entity._get_val_obj(value[0])
                    cont.set_val(value[1])
                    raw = cont.to_aper()
                else:
                    raw = value
            else:
                value: int = entity.get_val()
                raw = value.to_bytes(self._size)

            if self._size < self.DETERMINANT_SIZES[0]:
                return [raw]

            res: list[bytes] = []
            sizes, reminder = self._get_fragment_sizes(self._size)
            sizes: list[int] = [size for size, _ in sizes] + [reminder]
            for size in sizes:
                if bit_str:
                    size = size >> 3
                res.append(raw[:size])
                raw = raw[size:]
            return res

        if isinstance(entity, CHOICE):
            value = entity.get_val()
            choice: ASN1Obj = entity._cont[value[0]]
            choice.set_val(value[1])
            parent = choice._parent
            choice._parent = entity
            res = choice.to_aper()
            choice._parent = parent
            return [res]

        if isinstance(entity, (SET, SEQ)):
            root_canon: list[str]
            if isinstance(entity, SET):
                root_canon = entity._root_canon
            else:
                root_canon = entity._root

            res = b""
            for ident in root_canon:
                value = entity.get_val()
                if ident in value:
                    # component present in the encoding
                    component: ASN1Obj = entity._cont[ident]
                    parent = component._parent
                    component._parent = entity
                    component.set_val(value[ident])
                    res += component.to_aper()
                    component._parent = parent
            return [res]

        return []

    def raw(self) -> bytes:
        """Return the raw encoded data of the APER entity.

        This method generates the full encoded representation of the APER entity as raw bytes.
        The raw encoding includes the preamble, length determinants, and all fragments.

        Returns:
            bytes: The raw encoded data of the APER entity.
        """

        res: bytes
        preamble = self._preamble
        if pad := len(preamble) % 8:
            # pad is placed at the end for the preamble
            preamble = preamble + self._encode_pad(pad)
        res = preamble.tobytes()

        for ldet, frag in zip_longest(self._len_dets, self.fragments, fillvalue=b""):
            if pad := len(ldet) % 8:
                # pad is placed at the beginning for the length determinant
                ldet = self._encode_pad(pad) + ldet
            res += bytes(ldet) + frag

        return res

    @property
    def preamble(self) -> str:
        """The preamble of the APER encoded entity as bit-string."""

        return self._preamble.to01()

    @preamble.setter
    def preamble(self, value: str) -> None:
        self._preamble = bitarray(value)

    @property
    def length(self) -> int:
        """The total length of the data contained in this APER encoded entity."""

        return self._size

    @length.setter
    def length(self, value: int):
        self._len_dets = self._compute_len_dets(value)

    @property
    def len_dets(self) -> list[bytes]:
        """The list of length determinants for the APER encoded entity."""

        return [arr.tobytes() for arr in self._len_dets]

    @property
    def length_unit(self) -> str:
        """The unit of measurement for the length of the encoded entity."""

        return self._length_unit
