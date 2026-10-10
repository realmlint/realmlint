#!/usr/bin/env bash
# Installs a realmlint release binary after verifying its checksum.
#
# Usage: install.sh [-b BINARY] [-v VERSION] [-d DIR]
#   -b BINARY   realmlint (default) or realmlint-agent
#   -v VERSION  release to install, such as 1.0.0, or "latest" (default)
#   -d DIR      directory to install into (default: ~/.local/bin)
#
# Works on Linux, macOS and Windows (Git Bash) for amd64 and arm64.
# GITHUB_TOKEN, if set, is used to look up the latest release without
# hitting API rate limits.
set -euo pipefail

repo="realmlint/realmlint"
# Overridable for testing against a local copy of a release.
base="${REALMLINT_DOWNLOAD_BASE:-https://github.com/$repo/releases/download}"
version="latest"
dir="${HOME}/.local/bin"
name="realmlint"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; }
fail() { echo "install.sh: $*" >&2; exit 1; }

while getopts "b:v:d:h" opt; do
  case "$opt" in
    b) name="$OPTARG" ;;
    v) version="$OPTARG" ;;
    d) dir="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

case "$name" in
  realmlint | realmlint-agent) ;;
  *) fail "unknown binary $name (use realmlint or realmlint-agent)" ;;
esac

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *) fail "unsupported operating system: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported architecture: $(uname -m)" ;;
esac

if [[ "$version" == "latest" ]]; then
  auth=()
  [[ -n "${GITHUB_TOKEN:-}" ]] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  version="$(curl -fsSL ${auth[@]+"${auth[@]}"} -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$repo/releases/latest" |
    grep -o '"tag_name": *"[^"]*"' | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')" ||
    fail "could not look up the latest release"
  [[ -n "$version" ]] || fail "could not look up the latest release"
fi
version="${version#v}"

ext=tar.gz
binary="$name"
if [[ "$os" == windows ]]; then
  ext=zip
  binary="$name.exe"
fi
archive="${name}_${version}_${os}_${arch}.${ext}"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT

curl -fsSL -o "$tmp/$archive" "$base/v$version/$archive" ||
  fail "could not download $archive for version $version"
curl -fsSL -o "$tmp/checksums.txt" "$base/v$version/checksums.txt" ||
  fail "could not download checksums for version $version"

expected="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[[ -n "$expected" ]] || fail "no checksum listed for $archive"
if command -v sha256sum >/dev/null; then
  actual="$(sha256sum "$tmp/$archive" | cut -d' ' -f1)"
else
  actual="$(shasum -a 256 "$tmp/$archive" | cut -d' ' -f1)"
fi
[[ "$actual" == "$expected" ]] || fail "checksum mismatch for $archive (expected $expected, got $actual)"

if [[ "$ext" == zip ]]; then
  unzip -q "$tmp/$archive" "$binary" -d "$tmp/out"
else
  mkdir -p "$tmp/out"
  tar -xzf "$tmp/$archive" -C "$tmp/out" "$binary"
fi

mkdir -p "$dir"
cp "$tmp/out/$binary" "$dir/$binary"
chmod +x "$dir/$binary"
echo "Installed $name $version to $dir/$binary"
