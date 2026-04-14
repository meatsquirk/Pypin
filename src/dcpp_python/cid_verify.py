"""Compatibility shim for dcpp_python.crypto.cid."""

from dcpp_python.crypto.cid import *  # noqa: F401,F403
from dcpp_python.crypto.cid import (  # noqa: F401
    _base32_decode,
    _base32_encode,
    _decode_varint,
    _encode_varint,
)
