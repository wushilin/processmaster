#!/usr/bin/env bash
# package.bash v0.1
# Usage: ./package.bash <tag>
# Example: ./package.bash v0.1

set -euo pipefail

# Check input
if [ $# -ne 1 ]; then
    echo "Usage: $0 <tag>"
    exit 1
fi

TAG="$1"
DIST_DIR="dist"
BINARIES=("target/release/processmaster" "target/release/pmctl")

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

TARBALL="${DIST_DIR}/processmaster-${TAG}-${ARCH}.tar.gz"

# Create dist directory if it doesn't exist
mkdir -p "$DIST_DIR"

# Verify binaries exist
for bin in "${BINARIES[@]}"; do
    if [ ! -f "$bin" ]; then
        echo "Error: $bin not found."
        exit 1
    fi
done

# Create tarball with files at root
tar -C target/release -czf "$TARBALL" "${BINARIES[@]##*/}"

echo "Created package: $TARBALL"
