import pytest
from hypothesis import given, settings, strategies as st

from dcpp_python.core.framing import (
    ChecksumError,
    FramingError,
    MagicBytesError,
    MessageTooLargeError,
    Profile1Framer,
)


@pytest.mark.fuzz
@given(data=st.binary(min_size=0, max_size=256))
@settings(max_examples=50, deadline=None)
def test_profile1_decode_rejects_invalid_frames(data):
    try:
        frame = Profile1Framer.decode(data)
    except (FramingError, MagicBytesError, ChecksumError, MessageTooLargeError):
        return

    assert frame is not None
