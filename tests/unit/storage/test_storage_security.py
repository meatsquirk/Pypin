from pathlib import Path

import pytest

from dcpp_python.storage import FileSystemGenesisStore, FileSystemStorage


def _is_within_base(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def test_collection_id_safe_remains_readable(temp_storage: FileSystemStorage) -> None:
    collection_id = "eth:0xabc123"
    path = temp_storage._collection_path(collection_id)
    assert path.name == "eth_0xabc123"
    assert _is_within_base(path, temp_storage.base_path)


@pytest.mark.parametrize(
    "collection_id",
    [
        "..",
        "../evil",
        "a/../b",
        r"..\\evil",
        "a:b/../c",
    ],
)
def test_collection_id_unsafe_is_hashed(temp_storage: FileSystemStorage, collection_id: str) -> None:
    path = temp_storage._collection_path(collection_id)
    assert path.name.startswith("collection_")
    assert _is_within_base(path, temp_storage.base_path)


def test_collection_id_empty_raises(temp_storage: FileSystemStorage) -> None:
    with pytest.raises(ValueError):
        temp_storage._collection_path("")


def test_genesis_collection_id_safe_remains_readable(tmp_path: Path) -> None:
    store = FileSystemGenesisStore(tmp_path)
    collection_id = "eth:0xabc123"
    path = store._genesis_file(collection_id)
    assert path.name == "eth_0xabc123.json"
    assert _is_within_base(path, store.genesis_path)


@pytest.mark.parametrize(
    "collection_id",
    [
        "..",
        "../evil",
        "a/../b",
        r"..\\evil",
        "a:b/../c",
    ],
)
def test_genesis_collection_id_unsafe_is_hashed(tmp_path: Path, collection_id: str) -> None:
    store = FileSystemGenesisStore(tmp_path)
    path = store._genesis_file(collection_id)
    assert path.name.startswith("collection_")
    assert path.name.endswith(".json")
    assert _is_within_base(path, store.genesis_path)
