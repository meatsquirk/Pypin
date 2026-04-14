# DCPP Python

DCPP Python is a reference implementation of the Distributed Content Preservation Protocol (DCPP) wire protocol.
It focuses on correct framing, message validation, manifest handling, and pluggable networking backends.

## Highlights

- RFC-aligned framing and message types
- Storage backends with CID verification
- Libp2p and BitTorrent optional integrations
- Strong test coverage with unit, integration, and e2e suites

## Quick Start

```bash
pip install -e .
python3 -m pytest -m "not benchmark"
```

See Getting Started for a deeper walkthrough.
