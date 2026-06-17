#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BT_CLEAN_BASE_URL:-__BASE_URL__}"
VERSION="${BT_CLEAN_VERSION:-20260617}"
ARCHIVE="${BT_CLEAN_ARCHIVE:-bt-clean-${VERSION}.tar.gz}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo env BT_CLEAN_BASE_URL=https://your-domain/path bash install.sh"
  exit 1
fi

if [ "$BASE_URL" = "__BASE_URL__" ]; then
  echo "ERROR: set BT_CLEAN_BASE_URL, or replace __BASE_URL__ in this script."
  echo "Example: curl -fsSL https://your-domain/bt-clean/install.sh | sudo env BT_CLEAN_BASE_URL=https://your-domain/bt-clean bash"
  exit 1
fi

BASE_URL="${BASE_URL%/}"
TMP_DIR="$(mktemp -d /tmp/bt-clean.XXXXXX)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cd "$TMP_DIR"

download() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --connect-timeout 15 --retry 3 -o "$output" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$output" "$url"
  else
    echo "ERROR: curl or wget is required."
    exit 1
  fi
}

echo "Downloading $ARCHIVE from $BASE_URL ..."
download "$BASE_URL/$ARCHIVE" "$ARCHIVE"
download "$BASE_URL/SHA256SUMS" SHA256SUMS || true

if [ -s SHA256SUMS ] && command -v sha256sum >/dev/null 2>&1; then
  grep "  $ARCHIVE\$" SHA256SUMS | sha256sum -c -
fi

tar -xzf "$ARCHIVE"
cd bt-clean
chmod +x install-ubuntu_6.0_clean.sh

echo "Starting installer ..."
bash install-ubuntu_6.0_clean.sh
