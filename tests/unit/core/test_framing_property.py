import pytest
from hypothesis import given, settings, strategies as st

from dcpp_python.core.constants import MessageType
from dcpp_python.core.framing import Profile1Framer


CBOR_PRIMITIVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-2**31, max_value=2**31 - 1),
    st.text(min_size=0, max_size=64),
    st.binary(min_size=0, max_size=128),
)

CBOR_PAYLOADS = st.recursive(
    CBOR_PRIMITIVES,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(min_size=1, max_size=32), children, max_size=8),
    ),
    max_leaves=32,
)


@pytest.mark.fuzz
@given(payload=CBOR_PAYLOADS)
@settings(max_examples=50, deadline=None)
def test_profile1_roundtrip_property(payload):
    framed = Profile1Framer.encode(MessageType.HELLO, payload)
    decoded = Profile1Framer.decode(framed)

    assert decoded.message_type == MessageType.HELLO
    if isinstance(payload, bytes):
        assert decoded.payload == payload
    else:
        assert decoded.decode_payload() == payload
