# Pinned cross-compile builder for rine-mls.
# NEVER build on the production CX22 — this image only ever runs on the dev
# workstation / CI, following the ship-broker.sh precedent.
FROM rust:1.88-bookworm

# Pin every tool exactly, same discipline as the crate's Cargo.toml pins.
ARG ZIG_VERSION=0.13.0
ARG CARGO_ZIGBUILD_VERSION=0.19.8
ARG MATURIN_VERSION=1.9.4

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl xz-utils python3 python3-pip ca-certificates file \
    && rm -rf /var/lib/apt/lists/*

# zig — the cross-linker cargo-zigbuild and maturin's --zig both shell out to.
RUN curl -sSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
    -o /tmp/zig.tar.xz \
    && tar -xf /tmp/zig.tar.xz -C /opt \
    && ln -s "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

RUN cargo install --locked cargo-zigbuild --version "=${CARGO_ZIGBUILD_VERSION}"
RUN pip3 install --break-system-packages --no-cache-dir "maturin==${MATURIN_VERSION}"

RUN rustup target add \
    x86_64-unknown-linux-gnu \
    aarch64-unknown-linux-gnu \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    x86_64-apple-darwin \
    aarch64-apple-darwin \
    wasm32-unknown-unknown

WORKDIR /work
