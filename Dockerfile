# DCPP Python Node Dockerfile
#
# Build a DCPP Python node with full P2P and BitTorrent support
#
# Usage:
#   docker build -t dcpp-python .
#   docker run -p 4001:4001 dcpp-python --collection eth:0xBC4CA0

FROM python:3.11-slim-bookworm AS builder

# Install build dependencies for native extensions
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libffi-dev \
    libgmp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python package files
COPY pyproject.toml README.md ./

# Copy source code (src layout required by pyproject)
COPY src/ src/

# Install dependencies (including py-libp2p from the pinned upstream archive)
# Set environment for fastecdsa compilation
ENV CFLAGS="-I/usr/include" \
    LDFLAGS="-L/usr/lib" \
    LIBRARY_PATH="/usr/lib" \
    C_INCLUDE_PATH="/usr/include"

RUN pip install --default-timeout=120 --no-cache-dir -e ".[dev,bittorrent,p2p]" aiohttp

# Verify libp2p is installed correctly in builder (optional)
RUN python -c "from libp2p import new_host; print('libp2p import OK')" || \
    echo "libp2p not available - continuing without P2P support"

# Runtime image
FROM python:3.11-slim-bookworm

# Install runtime dependencies for native extensions
# libp2p requires: libssl3, libgmp10, libffi8 (for cffi/cryptography)
# curl is needed for Docker healthcheck
RUN apt-get update && apt-get install -y \
    libssl3 \
    libgmp10 \
    libffi8 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder (includes libp2p and all dependencies)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
# Copy any binary scripts installed by pip (if any)
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app/src /app/src

# Verify libp2p is available in runtime image
RUN python -c "from libp2p import new_host; print('libp2p runtime import OK')" || \
    echo "WARNING: libp2p import failed in runtime image (P2P features disabled)"

# Copy tests for verification
COPY tests/ /app/tests/

# Create data directory
RUN mkdir -p /data/dcpp

# Default ports
EXPOSE 4001
EXPOSE 8080

# Environment variables
ENV PYTHONPATH=/app/src \
    DCPP_LISTEN_ADDR=0.0.0.0:4001 \
    DCPP_DATA_DIR=/data/dcpp \
    DCPP_STUB_MODE=0 \
    DCPP_BT_ALLOW_LOCAL=1

# Health check (HTTP API is enabled by default on port 8080)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

# Default command - run the daemon
ENTRYPOINT ["python", "-m", "dcpp_python.node.daemon"]
CMD ["--listen", "0.0.0.0:4001"]
