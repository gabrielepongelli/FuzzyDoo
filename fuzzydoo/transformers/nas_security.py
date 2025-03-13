import binascii
import base64
from typing import override

from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_mobile.TS24501_FGMM import FGMMSecProtNASMessage
from pycrate_core.utils import PycrateErr
from pycrate_core.base import Buf
from CryptoMobile.Milenage import Milenage
from CryptoMobile.conv import conv_501_A2, conv_501_A6, conv_501_A7, conv_501_A8

from ..transformer import Encoder, Decoder, Transformer
from ..protocol import Message, MessageParsingError
from ..proto.nas.messages import NASMessage
from ..utils.register import register

from ..utils.errs import *


@register(Transformer)
class NASSecurity(Encoder, Decoder):
    """Handles NAS (Non-Access Stratum) security operations for 5G networks.

    This class implements both encoding and decoding functionalities for NAS messages, focusing on 
    security aspects such as encryption, decryption, and integrity protection. It manages key 
    derivation, ciphering, and integrity algorithms as specified in 3GPP standards for 5G NAS 
    security.

    The class utilizes the Milenage algorithm for authentication and key agreement, and implements 
    the key derivation functions defined in 3GPP TS 33.501.

    The class provides methods to extract security parameters from NAS messages,
    perform encryption and decryption, and compute message authentication codes (MAC).
    """

    def __init__(self, op: str, op_type: str, key: str, mcc: int, mnc: int, supi: str):
        """Initialize a new `NASSecurity` instance.

        Args:
            op: Operator code or Operator Code with Customization **in hexadecimal format**.
            op_type: Type of operator code (`'OP'` or `'OPC'`).
            key: Subscriber's key **in hexadecimal format**.
            mcc: Mobile Country Code.
            mnc: Mobile Network Code.
            supi: Subscription Permanent Identifier.
        """

        # UE's data
        self._ue_op: bytes = binascii.unhexlify(op)
        """Operator code or Operator Code with Customization."""
        self._ue_key: bytes = binascii.unhexlify(key)
        """Subscriber's key."""
        self._ue_op_type: str = op_type
        """Type of operator code (`'OP'` or `'OPC'`)."""
        self._ue_sn_name: bytes = f"5G:mnc{mnc:03d}.mcc{mcc:03d}.3gppnetwork.org".encode()
        """Serving network name."""
        self._ue_supi: str = supi
        """Subscription Permanent Identifier."""

        # First step derived data
        self._k_amf: bytes | None = None
        """K_AMF key derived from K_SEAF."""

        # Final derived data
        self._ciph_alg: int | None = None
        """Selected ciphering algorithm."""
        self._integ_alg: int | None = None
        """Selected integrity algorithm."""
        self._k_nas_enc: bytes | None = None
        """NAS encryption key."""
        self._k_nas_int: bytes | None = None
        """NAS integrity key."""

    @property
    def ciphering_algorithm(self) -> int | None:
        """The selected ciphering algorithm (if already selected)."""

        return self._ciph_alg

    @property
    def integrity_algorithm(self) -> int | None:
        """The selected integrity algorithm (if already selected)."""

        return self._integ_alg

    @property
    def k_nas_enc(self) -> bytes | None:
        """The shared symmetric key to use for encryption and decryption operations (if already 
        calculated)"""

        return self._k_nas_enc

    @property
    def k_nas_int(self) -> bytes | None:
        """The shared symmetric key to use for integrity verification and calculation (if already 
        calculated)"""

        return self._k_nas_int

    @override
    def reset(self):
        self._k_amf = None

        self._ciph_alg = None
        self._integ_alg = None
        self._k_nas_enc = None
        self._k_nas_int = None

    def _extract_params(self, msg: NASMessage):
        """Extracts and computes security parameters from a NAS message.

        This function processes a NAS message to extract and compute various security parameters 
        such as K_AUSF, K_SEAF, K_AMF, K_NAS_ENC, and K_NAS_INT based on the message type.

        Args:
            msg: The NAS message from which to extract security parameters.
        """

        msg_content = msg.content
        msg_name = msg.name
        if msg_name == "FGMMAuthenticationRequestMessage":
            sqn_xor_ak, amf, _ = msg_content['AUTN']['AUTN'].values()
            rand = msg_content['RAND']['V']
            abba = msg_content['ABBA']['V']

            mil = Milenage(self._ue_op)
            if self._ue_op_type == 'OPC':
                mil.set_opc(self._ue_op)
            ak = mil.f5star(self._ue_key, rand)

            # ak ^ sqn_xor_ak
            sqn = bytes([a ^ b for a, b in zip(ak, sqn_xor_ak)])

            mil.f1(self._ue_key, rand, SQN=sqn, AMF=amf)
            _, ck, ik, _ = mil.f2345(self._ue_key, rand)

            # see CryptoMobile.conv for documentation of this function and arguments
            # get K_AUSF
            k_ausf = conv_501_A2(ck, ik, self._ue_sn_name, sqn_xor_ak)

            # get K_SEAF
            k_seaf = conv_501_A6(k_ausf, self._ue_sn_name)

            # get K_AMF
            self._k_amf = conv_501_A7(k_seaf, self._ue_supi.encode('ascii'), abba)
        elif msg.protected:
            inner = parse_NAS5G(msg.raw(), inner=True)[0][3]  # get the NASMessage field value
            if not isinstance(inner, Buf):
                msg_name = inner.__class__.__name__ + 'Message'
                msg_content = inner.get_val_d()
        if msg_name == "FGMMSecurityModeCommandMessage":
            nas_sec_alg = msg_content['NASSecAlgo']['NASSecAlgo']
            self._ciph_alg = nas_sec_alg['CiphAlgo']
            self._integ_alg = nas_sec_alg['IntegAlgo']

            # get K_NAS_ENC
            self._k_nas_enc = conv_501_A8(self._k_amf, alg_type=1, alg_id=self._ciph_alg)
            self._k_nas_enc = self._k_nas_enc[16:]

            # get K_NAS_INT
            self._k_nas_int = conv_501_A8(self._k_amf, alg_type=2, alg_id=self._integ_alg)
            self._k_nas_int = self._k_nas_int[16:]

    @override
    def transform(self, msg: NASMessage, src: str, dst: str) -> NASMessage:
        return msg

    @override
    def decode(self, msg: NASMessage, src: str, dst: str) -> NASMessage:
        """Decrypts a NAS message if it is encrypted.

        This function attempts to decrypt a NAS message using pre-extracted security parameters. If 
        the message is not encrypted or the necessary decryption keys are not available, it returns 
        the message unchanged.

        Args:
            msg: The NAS message to be decrypted.
            src: The source entity from which the message originates.
            dst: The destination entity to which the message is being sent.

        Raises:
            DecodingError: If the decryption process fails due to an error in parsing or decryption.

        Returns:
            NASMessage: The decrypted NAS message, or the original message if decryption is not
                applicable.
        """

        if msg.protocol != 'NAS-MM':
            return msg

        self._extract_params(msg)

        if self._k_nas_enc is None or self._ciph_alg is None:
            # if we don't yet have the necessary elements to decrypt the message, go ahead
            return msg

        if not msg.protected:
            # if the message is not security-protected, go ahead
            return msg

        sec_header = msg.content['5GMMHeaderSec']
        seqn = msg.content['Seqn']

        if sec_header['SecHdr'] in {2, 4}:
            try:
                # pylint: disable=protected-access
                direction = 0 if src == 'UE' else 1
                msg._content.decrypt(
                    self._k_nas_enc,
                    dir=direction,
                    fgea=self._ciph_alg,
                    seqnoff=0,
                    bearer=1
                )
            except PycrateErr as e:
                raise DecodingError(str(e)) from e

        nas_msg, err = parse_NAS5G(msg.content['NASMessage'], inner=False)
        if err:
            raise DecodingError(f"An unknow error occurred while decoding the message: {err}")

        msg_name = nas_msg.__class__.__name__ + 'Message'
        try:
            res = Message.from_name(msg.protocol, msg_name).parse(msg.content['NASMessage'])

            # pylint: disable=protected-access
            res._sec_header = sec_header
            res._seqn = seqn
            return res
        except MessageParsingError as e:
            raise DecodingError(str(e)) from e

    @override
    def encode(self, msg: NASMessage, src: str, dst: str) -> NASMessage:
        """Encrypts a NAS message and computes its MAC if applicable.

        This function encrypts a NAS message using pre-extracted security parameters and computes 
        the MAC if the necessary keys and algorithms are available.

        Args:
            msg: The NAS message to be encrypted.
            src: The source entity from which the message originates.
            dst: The destination entity to which the message is being sent.

        Raises:
            EncodingError: If the encryption or MAC computation process fails due to an error.

        Returns:
            NASMessage: The encrypted NAS message with the MAC computed, or the original message if 
                encryption and MAC computation are not applicable.
        """

        if msg.protocol != 'NAS-MM':
            return msg

        if self._k_nas_enc is None or self._ciph_alg is None:
            # if we don't yet have the necessary elements to encrypt the message, go ahead
            return msg

        if self._k_nas_int is None or self._integ_alg is None:
            # if we don't yet have the necessary elements to calculate the MAC of the message, go
            # ahead
            return msg

        if not hasattr(msg, '_sec_header') or not hasattr(msg, '_seqn'):
            return msg

        # pylint: disable=protected-access
        encrypted: bool = msg._sec_header['SecHdr'] in {2, 4}
        integrity_protected: bool = msg._sec_header['SecHdr'] != 0

        final_msg = msg
        if encrypted:
            ies = {
                '5GMMHeaderSec': msg._sec_header,
                'Seqn': msg._seqn,
                'NASMessage': msg.raw()
            }
            final_msg = FGMMSecProtNASMessage(val=ies)
        elif integrity_protected:
            # pylint: disable=protected-access
            ies = {
                '5GMMHeaderSec': msg._sec_header,
                'Seqn': msg._seqn,
                'NASMessage': msg._content[-1].to_bytes()
            }
            final_msg = FGMMSecProtNASMessage(val=ies)

        try:
            direction = 0 if src == 'UE' else 1
            if encrypted:
                final_msg.encrypt(
                    key=self._k_nas_enc,
                    dir=direction,
                    fgea=self._ciph_alg,
                    seqnoff=0,
                    bearer=1
                )

            if integrity_protected:
                final_msg.mac_compute(
                    key=self._k_nas_int,
                    dir=direction,
                    fgia=self._integ_alg,
                    seqnoff=0,
                    bearer=1
                )

            return msg.parse(final_msg.to_bytes())
        except (PycrateErr, MessageParsingError) as e:
            raise EncodingError(str(e)) from e

    @override
    def export_data(self) -> list[tuple[str, bytes]]:
        res = ""
        res += f"CIPHERING_ALGORITHM={self.ciphering_algorithm}\n"
        res += f"INTEGRITY_ALGORITHM={self.integrity_algorithm}\n"
        res += f"K_NAS_ENC={base64.b64encode(self.k_nas_enc)}\n"
        res += f"K_NAS_INT={base64.b64encode(self.k_nas_int)}\n"
        return [("enc_and_int_params.txt", res.encode())]
