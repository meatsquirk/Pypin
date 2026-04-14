"""Create a minimal manifest and serialize it to CBOR."""

from __future__ import annotations

import time

from dcpp_python.core.constants import AccessMode, CollectionType, ItemStatus, StorageType
from dcpp_python.manifest.manifest import Item, Manifest, TorrentInfo


def main() -> None:
    now = int(time.time())

    torrent = TorrentInfo(
        infohash="0" * 40,
        magnet="magnet:?xt=urn:btih:0000000000000000000000000000000000000000",
        piece_length=262144,
    )

    item = Item(
        item_id="item-1",
        name="example.txt",
        cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        size_bytes=24,
        mime_type="text/plain",
        storage_type=StorageType.LOCAL,
        status=ItemStatus.AVAILABLE,
    )

    manifest = Manifest(
        protocol="dcpp/1.0",
        type=CollectionType.CUSTOM,
        access_mode=AccessMode.PUBLIC,
        collection_id="example:collection",
        name="Example Collection",
        version=1,
        created_at=now,
        updated_at=now,
        total_items=1,
        total_size_bytes=item.size_bytes,
        merkle_root="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        torrent=torrent,
        items=[item],
    )

    payload = manifest.to_cbor()
    print(f"Manifest bytes: {len(payload)}")


if __name__ == "__main__":
    main()
