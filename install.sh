#!/bin/sh
# Install policygate on macOS or Linux.
#
# The binary goes to ~/.policygate/bin, which needs no privileges: policygate
# guards its own executable wherever it is installed, so the install location is
# a matter of convenience rather than of protection.
#
# This script is not meant to be piped into a shell. Download it, read it, then
# run it - policygate's own rules deny `curl ... | sh`, and a tool that asks you
# to trust an unread script has no business telling you not to.
set -eu

REPO="nobuo-miura/PolicyApprovalGate"
VERSION=""
INSTALL_DIR=""

usage() {
	cat <<'EOF'
Usage: install.sh [--version TAG] [--dir PATH]

  --version TAG  install a specific release (default: the newest published)
  --dir PATH     install into PATH (default: ~/.policygate/bin)
  --help         print this message
EOF
}

fail() {
	echo "install.sh: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version)
		[ $# -ge 2 ] || fail "--version requires a value"
		VERSION="$2"
		shift 2
		;;
	--version=*)
		VERSION="${1#--version=}"
		shift
		;;
	--dir)
		[ $# -ge 2 ] || fail "--dir requires a value"
		INSTALL_DIR="$2"
		shift 2
		;;
	--dir=*)
		INSTALL_DIR="${1#--dir=}"
		shift
		;;
	--help | -h)
		usage
		exit 0
		;;
	*)
		fail "unknown argument: $1"
		;;
	esac
done

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

case "$(uname -s)" in
Darwin) OS="darwin" ;;
Linux) OS="linux" ;;
*) fail "unsupported operating system: $(uname -s). Windows uses install.ps1." ;;
esac

MACHINE=$(uname -m)
# Under Rosetta 2 a shell on Apple silicon reports itself as x86_64, which
# describes the process rather than the machine. Following it would install an
# emulated build on a native host.
if [ "$OS" = "darwin" ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then
	MACHINE="arm64"
fi

case "$MACHINE" in
x86_64 | amd64) ARCH="amd64" ;;
arm64 | aarch64) ARCH="arm64" ;;
*) fail "unsupported architecture: $MACHINE" ;;
esac

# Releases are drafted first and published by hand once checked, so "latest"
# always answers with a real, reviewed release - never a draft in progress.
#
# The tr splits the response one field to a line before sed reads it. Without
# that, a greedy .* run across a whole response reaches the *last* tag_name in
# it, so a body that arrived unformatted would quietly install the oldest
# release instead of the newest - a downgrade reported as a success.
if [ -z "$VERSION" ]; then
	VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
		tr ',' '\n' |
		sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -n 1)
	[ -n "$VERSION" ] || fail "could not determine the newest release; pass --version"
fi

NAME="policygate_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$VERSION"

WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

echo "install.sh: downloading $NAME ($VERSION)"
curl -fsSL "$BASE/$NAME" -o "$WORK/$NAME" || fail "download failed: $BASE/$NAME"
curl -fsSL "$BASE/SHA256SUMS" -o "$WORK/SHA256SUMS" || fail "download failed: $BASE/SHA256SUMS"

# Verify before unpacking. An archive is only opened once its checksum matches
# the one published with the release.
if command -v sha256sum >/dev/null 2>&1; then
	ACTUAL=$(sha256sum "$WORK/$NAME" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
	ACTUAL=$(shasum -a 256 "$WORK/$NAME" | cut -d' ' -f1)
else
	fail "neither sha256sum nor shasum is available, so the download cannot be verified"
fi

# SHA256SUMS is written with a ./ prefix on each name.
EXPECTED=$(awk -v want="./$NAME" '$2 == want { print $1 }' "$WORK/SHA256SUMS")
[ -n "$EXPECTED" ] || fail "$NAME is not listed in SHA256SUMS"
[ "$ACTUAL" = "$EXPECTED" ] || fail "checksum mismatch for $NAME
  expected $EXPECTED
  actual   $ACTUAL"
echo "install.sh: checksum verified"

[ -n "$INSTALL_DIR" ] || INSTALL_DIR="$HOME/.policygate/bin"
mkdir -p "$INSTALL_DIR"
tar -xzf "$WORK/$NAME" -C "$WORK" policygate || fail "could not unpack $NAME"
chmod 0755 "$WORK/policygate"
# Replace by rename so an existing binary is never half-written, and so a
# running one is not written through.
mv "$WORK/policygate" "$INSTALL_DIR/policygate"

BIN="$INSTALL_DIR/policygate"
echo "install.sh: installed $("$BIN" version) to $BIN"

"$BIN" init || fail "could not create the configuration"

echo
echo "Next: register the hook with the host you use."
echo
echo "  $BIN install-hook --host claude    # ./.claude/settings.local.json"
echo "  $BIN install-hook --host codex     # ~/.codex/config.toml"
echo
echo "Then check the result:"
echo
echo "  $BIN doctor"

# A trailing slash changes how the entry is written without changing where it
# points, and comparing the two as written reports a directory as missing when
# it is already there - sending the reader off to add it a second time. The
# surrounding colons keep a longer neighbour such as .../bin2 from matching.
WANT="${INSTALL_DIR%/}"
HAVE=$(printf '%s' ":${PATH}:" | sed 's|/*:|:|g')

case "$HAVE" in
*":$WANT:"*) ;;
*)
	echo
	echo "$INSTALL_DIR is not on your PATH. The hook runs by absolute path and"
	echo "works regardless, but adding it lets you run policygate by name:"
	echo
	echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
	;;
esac
