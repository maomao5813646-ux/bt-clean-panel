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
  tr -d '\r' < SHA256SUMS > SHA256SUMS.clean
  checksum_line="$(awk -v file="$ARCHIVE" '$2 == file { print; exit }' SHA256SUMS.clean)"
  if [ -n "$checksum_line" ]; then
    printf '%s\n' "$checksum_line" | sha256sum -c -
  else
    echo "WARNING: checksum for $ARCHIVE not found in SHA256SUMS, skipping checksum."
  fi
fi

tar -xzf "$ARCHIVE"
if [ -d bt-clean ]; then
  cd bt-clean
fi
chmod +x install-ubuntu_6.0_clean.sh

echo "Starting installer ..."
bash install-ubuntu_6.0_clean.sh

INSTALL_URL="${BT_CLEAN_INSTALL_URL:-https://github.com/maomao5813646-ux/bt-clean-panel/releases/latest/download/install.sh}"
UPDATE_BASE_URL="${BT_CLEAN_UPDATE_BASE_URL:-https://github.com/maomao5813646-ux/bt-clean-panel/releases/latest/download}"
cat > /usr/local/bin/bt-clean-update <<EOF
#!/usr/bin/env bash
set -euo pipefail

INSTALL_URL="\${BT_CLEAN_INSTALL_URL:-$INSTALL_URL}"
BASE_URL="\${BT_CLEAN_BASE_URL:-$UPDATE_BASE_URL}"

if [ "\$(id -u)" -ne 0 ]; then
  echo "Please run as root: sudo bt-clean-update"
  exit 1
fi

if [ "\${1:-}" = "-h" ] || [ "\${1:-}" = "--help" ]; then
  echo "Usage: sudo bt-clean-update"
  echo "Override source: sudo env BT_CLEAN_INSTALL_URL=... BT_CLEAN_BASE_URL=... bt-clean-update"
  exit 0
fi

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "\$INSTALL_URL" | env BT_CLEAN_BASE_URL="\$BASE_URL" bash
elif command -v wget >/dev/null 2>&1; then
  wget -qO- "\$INSTALL_URL" | env BT_CLEAN_BASE_URL="\$BASE_URL" bash
else
  echo "ERROR: curl or wget is required."
  exit 1
fi
EOF
chmod +x /usr/local/bin/bt-clean-update
echo "Update command installed: sudo bt-clean-update"
