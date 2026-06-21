#!/usr/bin/env bash
# gen-signing-key.sh — generate an ed25519 keypair for trusted-agents list signing.
#
# Prints:
#   PRIVATE KEY (hex) — keep secret; used by the signing step in CI.
#   PUBLIC KEY  (hex) — embed via:
#     go build -ldflags "-X github.com/pilot-protocol/trustedagents.embeddedPubKeyHex=<64-hex-chars>"
#
# Usage: bash scripts/gen-signing-key.sh
set -euo pipefail

go run - <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PRIVATE KEY (hex, keep secret): %s\n", hex.EncodeToString(priv))
	fmt.Printf("PUBLIC KEY  (hex, for embedding): %s\n", hex.EncodeToString(pub))
}
EOF
