#!/usr/bin/env bash
# gen-signing-key.sh — generate an ed25519 keypair for trusted-agents list signing.
#
# The PRIVATE key is written to a file with 0600 permissions and is NEVER
# printed to the terminal or any log. Only PUBLIC material is printed to
# stdout:
#   - PUBLIC KEY (hex)    — embed via:
#       go build -ldflags "-X github.com/pilot-protocol/trustedagents.embeddedPubKeyHex=<64-hex-chars>"
#   - PUBLIC KEY (base64) — the value for the optional per-entry `public_key`
#       pin field in trusted-agents.json (the keyring expects std-base64).
#
# Usage:
#   bash scripts/gen-signing-key.sh [output-file]
#
# output-file defaults to ./signing-key.hex. KEEP THIS FILE SECRET — it is
# the signing private key. Do NOT commit it (it is gitignored).
set -euo pipefail

OUT_FILE="${1:-signing-key.hex}"

if [[ -e "$OUT_FILE" ]]; then
	echo "error: refusing to overwrite existing file: $OUT_FILE" >&2
	echo "       remove it or pass a different output path." >&2
	exit 1
fi

# Resolve the output path to an absolute one before we cd into a temp dir
# to build the helper, so a relative OUT_FILE still lands where the operator
# invoked the script.
case "$OUT_FILE" in
	/*) ABS_OUT="$OUT_FILE" ;;
	*)  ABS_OUT="$PWD/$OUT_FILE" ;;
esac

# Create the file with 0600 perms BEFORE writing any secret into it, so the
# private key is never world/group readable, not even for an instant.
umask 077
: > "$ABS_OUT"
chmod 600 "$ABS_OUT"

# `go run -` (stdin) is not portable across Go versions, so materialise the
# helper in a private temp dir and run it from there.
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cat > "$WORKDIR/main.go" <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	privFile := os.Getenv("PRIV_FILE")
	if privFile == "" {
		fmt.Fprintln(os.Stderr, "error: PRIV_FILE not set")
		os.Exit(1)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Write the private key (hex) to the pre-created 0600 file only.
	f, err := os.OpenFile(privFile, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open private key file: %v\n", err)
		os.Exit(1)
	}
	if _, err := fmt.Fprintln(f, hex.EncodeToString(priv)); err != nil {
		_ = f.Close()
		fmt.Fprintf(os.Stderr, "error: write private key: %v\n", err)
		os.Exit(1)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error: close private key file: %v\n", err)
		os.Exit(1)
	}

	// Print ONLY public material to stdout.
	fmt.Printf("PRIVATE KEY written to: %s (mode 0600 — keep secret, do NOT commit)\n", privFile)
	fmt.Printf("PUBLIC KEY  (hex, for -ldflags embeddedPubKeyHex): %s\n", hex.EncodeToString(pub))
	fmt.Printf("PUBLIC KEY  (base64, for trusted-agents.json public_key pin): %s\n", base64.StdEncoding.EncodeToString(pub))
}
EOF

(
	cd "$WORKDIR"
	GOWORK=off GO111MODULE=off PRIV_FILE="$ABS_OUT" go run main.go
)

echo
echo "Done. The private key lives in: $ABS_OUT"
echo "Treat it as a secret: do not commit it, do not paste it into logs or chat."
