# netwatch container image. See docker-compose.yml for how to run it; the
# container needs the host's network and processes, and privileged mode.
#   docker build -t netwatch .

FROM node:22-bookworm-slim AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM rust:1-bookworm AS build
# The eBPF programs build with nightly and bpf-linker (aya). bpf-linker comes
# prebuilt: building it needs a matching LLVM.
ARG BPF_LINKER_VERSION=v0.12.0
RUN apt-get update && apt-get install -y --no-install-recommends zstd && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://github.com/aya-rs/bpf-linker/releases/download/${BPF_LINKER_VERSION}/bpf-linker-$(uname -m)-unknown-linux-musl.tar.zst" \
       | tar --zstd -x -C /usr/local/cargo/bin \
    && bpf-linker --version \
    && rustup toolchain install nightly --profile minimal --component rust-src
WORKDIR /src
COPY . .
COPY --from=ui /src/ui/dist ui/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p netwatch && cp target/release/netwatch /netwatch

FROM debian:trixie-slim
# curl for the GeoIP updater, CA certificates for feeds, Slack and the LLM.
# Host tools (sshd, journalctl, ip, tailscale) are run from the host itself.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /netwatch /usr/local/bin/netwatch
COPY scripts/netwatch-update-geoip scripts/docker-entrypoint.sh /usr/local/bin/
ENV NETWATCH_CONTAINER=1 RUST_LOG=info
VOLUME /var/lib/netwatch
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["netwatch", "status"]
ENTRYPOINT ["docker-entrypoint.sh"]
