#!/bin/sh
# Installs or upgrades netwatch from a GitHub release. Published with the docs:
#   curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh
#
# Linux gets a systemd service, macOS a launchd daemon; both start in observe
# mode and keep an existing /etc/netwatch/netwatch.toml.
#   NETWATCH_VERSION=v0.1.0   install that release instead of the latest
set -eu

REPO=gotempsh/netwatch

say() { printf '%s\n' "$*" >&2; }
die() {
    say "netwatch install: $*"
    exit 1
}
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

# Everything runs from main, so a download cut short executes nothing.
main() {
    need curl
    need tar

    case $(uname -s) in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    *) die "netwatch runs on Linux and macOS, not $(uname -s)" ;;
    esac
    case $(uname -m) in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) if [ "$os" = linux ]; then arch=aarch64; else arch=arm64; fi ;;
    *) die "no release for $(uname -m); build from source: https://gotempsh.github.io/netwatch/installation/" ;;
    esac
    if [ "$os" = linux ] && ! command -v systemctl >/dev/null 2>&1; then
        die "this installs a systemd service and systemctl isn't here; run the container instead: https://gotempsh.github.io/netwatch/docker/"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        sha256="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        sha256="shasum -a 256"
    else
        die "sha256sum or shasum is required to check the download"
    fi

    sudo=""
    if [ "$(id -u)" -ne 0 ]; then
        need sudo
        sudo=sudo
    fi

    version=${NETWATCH_VERSION:-latest}
    if [ "$version" = latest ]; then
        url=https://github.com/$REPO/releases/latest/download
    else
        url=https://github.com/$REPO/releases/download/$version
    fi
    asset=netwatch-$os-$arch

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT INT TERM

    say "downloading $asset ($version)"
    curl -fsL "$url/$asset.tar.gz" -o "$tmp/$asset.tar.gz" || die "download failed: $url/$asset.tar.gz"
    curl -fsL "$url/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $url/SHA256SUMS"
    grep " $asset.tar.gz\$" "$tmp/SHA256SUMS" >"$tmp/sum" || die "$asset.tar.gz is not listed in SHA256SUMS"
    (cd "$tmp" && $sha256 -c sum >/dev/null 2>&1) || die "checksum mismatch for $asset.tar.gz; nothing was installed"
    tar -xzf "$tmp/$asset.tar.gz" -C "$tmp"

    if [ "$os" = linux ]; then
        $sudo "$tmp/$asset/scripts/install.sh"
    else
        $sudo "$tmp/$asset/netwatch" install
    fi
}

main "$@"
