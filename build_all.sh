#!/usr/bin/env bash
# build_all.sh — build static musl binaries for both x86_64 (amd64) and aarch64.
#
# Uses cargo-zigbuild so both targets cross-compile from any host (the C deps,
# aws-lc-sys and ring, need a C cross toolchain; zig provides one for free).
#
# Usage:
#   ./build_all.sh            # just build
#   ./build_all.sh v0.3       # build and package dist/processmaster-v0.3-<arch>-musl.tar.gz
#
# Requirements: cargo-zigbuild (cargo install cargo-zigbuild) and zig on PATH
# (https://ziglang.org/download/). rustup targets are added automatically.

set -euo pipefail
cd "$(dirname "$0")"

TAG="${1:-}"
TARGETS=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl)
BINS=(processmaster pmctl)

command -v cargo-zigbuild >/dev/null || { echo "error: cargo-zigbuild not found (cargo install cargo-zigbuild)"; exit 1; }
command -v zig >/dev/null || { echo "error: zig not found on PATH (https://ziglang.org/download/)"; exit 1; }

for target in "${TARGETS[@]}"; do
    rustup target list --installed | grep -qx "$target" || rustup target add "$target"
done

for target in "${TARGETS[@]}"; do
    echo "==> building $target"
    cargo zigbuild --release --target "$target"
done

for target in "${TARGETS[@]}"; do
    arch="${target%%-*}"
    for bin in "${BINS[@]}"; do
        ls -l "target/$target/release/$bin"
    done
    if [ -n "$TAG" ]; then
        mkdir -p dist
        tarball="dist/processmaster-${TAG}-${arch}-musl.tar.gz"
        tar -C "target/$target/release" -czf "$tarball" "${BINS[@]}"
        echo "packaged $tarball"
    fi
done
