import pytest

from dcpp_python.core.constants import MessageType
from dcpp_python.core.framing import Profile1Framer


@pytest.mark.benchmark
def test_profile1_encode_benchmark(benchmark):
    payload = {"message": "hello", "counter": 123, "items": list(range(100))}
    benchmark(Profile1Framer.encode, MessageType.HELLO, payload)


@pytest.mark.benchmark
def test_profile1_decode_benchmark(benchmark):
    payload = {"message": "hello", "counter": 123, "items": list(range(100))}
    framed = Profile1Framer.encode(MessageType.HELLO, payload)
    benchmark(Profile1Framer.decode, framed)
