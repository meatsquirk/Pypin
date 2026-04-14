"""Minimal collection guardian flow using a storage backend."""

from __future__ import annotations

from pathlib import Path

from dcpp_python.storage import FileSystemStorage


def main() -> None:
    collection_id = "example:collection"
    content = b"Hello, guardian world."

    storage = FileSystemStorage(Path("./.guardian_storage"))
    cid, stored = storage.store_verified(collection_id, content)

    print(f"Stored content for {collection_id}: {stored} (cid={cid})")

    retrieved = storage.retrieve_verified(collection_id, cid)
    if retrieved is None:
        raise SystemExit("Failed to retrieve or verify content")

    print(f"Retrieved {len(retrieved)} bytes for cid={cid}")


if __name__ == "__main__":
    main()
