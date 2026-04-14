# Getting Started

## Install

```bash
pip install -e .
```

Optional extras:

```bash
pip install -e ".[dev]"
pip install -e ".[p2p]"
pip install -e ".[bittorrent]"
pip install -e ".[discovery]"
```

## Run Tests

```bash
python3 -m pytest -m "not benchmark"
```

## Run Benchmarks

```bash
python3 -m pytest -m benchmark --benchmark-only
```

## Environment Flags

- `DCPP_STUB_MODE=1` enables stub DHT operations for local testing.
- `DCPP_BT_ALLOW_LOCAL=1` allows the native BitTorrent backend without torf.

Example:

```bash
DCPP_STUB_MODE=0 DCPP_BT_ALLOW_LOCAL=0 python3 -m dcpp_python.node.client hello
```
