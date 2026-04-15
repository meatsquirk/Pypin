"""Construct and frame a HEALTH_PROBE message."""

from __future__ import annotations

import os

from dcpp_python.core.constants import MessageType
from dcpp_python.core.framing import Profile1Framer
from dcpp_python.core.messages import Challenge, HealthProbe


def main() -> None:
    challenge = Challenge(
        cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        offset=0,
        length=16,
    )

    probe = HealthProbe(
        collection_id="example:collection",
        challenges=[challenge],
        nonce=os.urandom(16),
    )

    framed = Profile1Framer.encode(MessageType.HEALTH_PROBE, probe.to_dict())
    print(f"Framed probe bytes: {len(framed)}")


if __name__ == "__main__":
    main()
