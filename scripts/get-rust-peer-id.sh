#!/usr/bin/env bash
set -euo pipefail

RUST_CONTAINER="${DCPP_RUST_CONTAINER:-dcpp-python-rust-1}"
PY_PROJECT="${DCPP_PY_COMPOSE_PROJECT:-dcpp-python}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not available in PATH" >&2
  exit 1
fi

if ! docker ps >/dev/null 2>&1; then
  echo "Docker daemon not running" >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${RUST_CONTAINER}$"; then
  echo "${RUST_CONTAINER} container is not running" >&2
  exit 1
fi

peer_id=$(
  docker logs "${RUST_CONTAINER}" 2>&1 \
    | grep -Eo 'Local Peer ID: (12D3KooW[[:alnum:]]+)' \
    | tail -n 1 \
    | awk '{print $4}' || true
)

if [[ -n "${peer_id}" ]]; then
  printf '%s\n' "${peer_id}"
  exit 0
fi

rust_ip=$(
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${RUST_CONTAINER}"
)

if [[ -z "${rust_ip}" ]]; then
  echo "Failed to resolve ${RUST_CONTAINER} container IP" >&2
  exit 1
fi

probe_containers=()
if [[ -n "${DCPP_PY_PROBE_CONTAINER:-}" ]]; then
  probe_containers+=("${DCPP_PY_PROBE_CONTAINER}")
fi

while IFS= read -r probe_container; do
  [[ -n "${probe_container}" ]] && probe_containers+=("${probe_container}")
done < <(
  docker ps \
    --filter "label=com.docker.compose.project=${PY_PROJECT}" \
    --filter "label=com.docker.compose.service=python-node-1" \
    --format '{{.Names}}'
)

while IFS= read -r probe_container; do
  [[ -n "${probe_container}" ]] && probe_containers+=("${probe_container}")
done < <(
  docker ps \
    --filter "label=com.docker.compose.project=${PY_PROJECT}" \
    --filter "label=com.docker.compose.service=python-node-2" \
    --format '{{.Names}}'
)

for probe_container in "${probe_containers[@]}"; do
  if ! docker ps --format '{{.Names}}' | grep -q "^${probe_container}$"; then
    continue
  fi

  peer_id=$(
    docker exec "${probe_container}" sh -lc "python - '${rust_ip}' <<'PY'
import re
import sys

import multiaddr
import trio
from libp2p import new_host
from libp2p.crypto.ed25519 import create_new_key_pair as create_ed25519_key_pair
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.security.noise.exceptions import PeerIDMismatchesPubkey
import libp2p.security.noise.patterns as patterns

rust_ip = sys.argv[1]
placeholder_kp = create_ed25519_key_pair()
placeholder_id = ID.from_pubkey(placeholder_kp.public_key)
peer_info = info_from_p2p_addr(
    multiaddr.Multiaddr(f'/ip4/{rust_ip}/tcp/4001/p2p/{placeholder_id}')
)
found_peer_id = None
orig_handshake_outbound = patterns.PatternXX.handshake_outbound


async def wrapped_handshake_outbound(self, conn, remote_peer):
    global found_peer_id
    try:
        return await orig_handshake_outbound(self, conn, remote_peer)
    except PeerIDMismatchesPubkey as exc:
        match = re.search(r'remote_peer_id_from_pubkey=(12D3KooW\\w+)', str(exc))
        if match:
            found_peer_id = match.group(1)
        raise


patterns.PatternXX.handshake_outbound = wrapped_handshake_outbound


async def main():
    host = new_host(
        key_pair=create_ed25519_key_pair(),
        muxer_preference='YAMUX',
    )
    try:
        async with host.run(listen_addrs=[multiaddr.Multiaddr('/ip4/0.0.0.0/tcp/4020')]):
            try:
                await host.connect(peer_info)
            except Exception:
                pass
    except Exception:
        pass

    if found_peer_id:
        print(found_peer_id)
        return

    raise SystemExit(1)


trio.run(main)
PY" 2>&1 \
      | tr -d '\r' \
      | grep -Eo '12D3KooW[[:alnum:]]+' \
      | tail -n 1 || true
  )

  if [[ -n "${peer_id}" ]]; then
    printf '%s\n' "${peer_id}"
    exit 0
  fi
done

echo "Failed to determine Rust peer ID from logs or live probe" >&2
exit 1
