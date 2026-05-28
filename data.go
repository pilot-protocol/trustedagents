// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trustedagents holds the build-time-embedded list of node IDs
// that the daemon auto-accepts handshake requests from. The data layer
// is utility-tier so both the daemon plugin (plugins/trustedagents)
// and the CLI (cmd/pilotctl) can read it without violating the strict
// downward layer rule.
//
// The list is plain JSON in this directory, embedded at build time and
// refreshed hourly from raw.githubusercontent.com by
// plugins/trustedagents.Run. Authenticity comes from HTTPS to GitHub
// plus repo write access — there is no separate signature check.
//
// Adding an agent: edit trusted-agents.json, commit. Daemons in the
// field pick it up within ~1h. Brand-new daemons get the embedded copy
// from the binary, so the feature works on first boot even airgapped.
package trustedagents

import (
	"crypto/ed25519"
	"encoding/base64"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
)

// Agent is one entry in the trusted-agents list. Match is by NodeID;
// Hostname and Address are kept for logs and `pilotctl trusted list`.
// Other JSON fields in the source file (tier, description, ...) are
// silently ignored on unmarshal — we don't care about them at runtime.
type Agent struct {
	Hostname string `json:"hostname"`
	Address  string `json:"address"`
	NodeID   uint32 `json:"node_id"`
}

//go:embed trusted-agents.json
var embeddedJSON []byte

// EmbeddedJSON returns the bytes of the embedded JSON list. Exposed for
// the plugin's HTTP refresher which needs to compare fetched bytes
// against the embedded baseline at startup.
func EmbeddedJSON() []byte {
	out := make([]byte, len(embeddedJSON))
	copy(out, embeddedJSON)
	return out
}

var (
	mu     sync.RWMutex
	byNode map[uint32]string // node_id -> name
	all    []Agent
)

func init() {
	if err := Load(embeddedJSON); err != nil {
		// CI guards this via TestEmbeddedListLoads; if it ever fires in
		// production, an empty list (zero auto-accepts) is the safe default.
		slog.Error("trustedagents: embedded list malformed", "err", err)
		mu.Lock()
		byNode = map[uint32]string{}
		mu.Unlock()
	}
}

// IsTrusted reports whether nodeID is in the trusted-agents list. The
// caller MUST verify the (node_id, public_key) binding at the registry
// before acting on a true result — this package only checks the list.
func IsTrusted(nodeID uint32) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	name, ok := byNode[nodeID]
	return name, ok
}

// SetForTest replaces the active list with agents and returns a restore
// function that reloads the embedded list. Test-only — never call from
// production code.
func SetForTest(agents []Agent) (restore func()) {
	idx := make(map[uint32]string, len(agents))
	for _, a := range agents {
		if a.NodeID == 0 {
			continue
		}
		idx[a.NodeID] = a.Hostname
	}
	mu.Lock()
	prevByNode, prevAll := byNode, all
	byNode = idx
	all = append([]Agent(nil), agents...)
	mu.Unlock()
	return func() {
		mu.Lock()
		byNode = prevByNode
		all = prevAll
		mu.Unlock()
	}
}

// All returns a copy of the current list. Used by `pilotctl trusted list`.
func All() []Agent {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Agent, len(all))
	copy(out, all)
	return out
}

// embeddedPubKey is the ed25519 public key used to verify the signature
// on the runtime-fetched trusted-agents JSON. When all 32 bytes are zero
// the key has not been configured yet and signature verification is
// skipped (backward-compatible). Set this to the real public key once the
// signing infrastructure is in place.
//
// TODO: inject via -ldflags at build time so the same binary can verify
// different lists (dev/staging/prod).
var embeddedPubKey = ed25519.PublicKey{
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

// VerifyAndStripSig checks the ed25519 signature embedded in the fetched
// JSON. If no "signature" field is present the raw body is returned as-is
// (backward-compatible with unsigned lists). If the field is present the
// signature is verified against embeddedPubKey; on mismatch an error is
// returned so the caller falls back to the embedded list.
func VerifyAndStripSig(raw []byte) ([]byte, error) {
	// Decode the entire doc to extract the signature field.
	var envelope struct {
		Agents    json.RawMessage `json:"agents"`
		Signature *string         `json:"signature,omitempty"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("verify: parse: %w", err)
	}

	// No signature → accept unsigned (backward compat).
	if envelope.Signature == nil || *envelope.Signature == "" {
		slog.Warn("trustedagents: fetched list has no signature — " +
			"accepting anyway (TLS-only trust). This will become a hard " +
			"error once signing is deployed.")
		return raw, nil
	}

	// Public key not configured → reject: a signature exists but we
	// cannot verify it. Accepting would defeat the purpose.
	if isZeroKey(embeddedPubKey) {
		return nil, fmt.Errorf("verify: signature present but embeddedPubKey is not configured")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(*envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("verify: bad signature encoding: %w", err)
	}

	// Re-marshal WITHOUT the signature to produce the exact payload the
	// signer committed to. The signer MUST use the same canonical form
	// (json.Marshal on this struct with Agents as json.RawMessage).
	envelope.Signature = nil
	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("verify: remarshal: %w", err)
	}

	if !ed25519.Verify(embeddedPubKey, payload, sigBytes) {
		return nil, fmt.Errorf("verify: signature mismatch")
	}

	slog.Info("trustedagents: signature verified", "agents", len(raw))
	return payload, nil
}

func isZeroKey(k ed25519.PublicKey) bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// Load parses raw JSON and atomically replaces the active list. Safe to
// call from any goroutine. Used by plugins/trustedagents.fetchOnce
// after each successful HTTP refresh.
func Load(raw []byte) error {
	var doc struct {
		Agents []Agent `json:"agents"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	idx := make(map[uint32]string, len(doc.Agents))
	for _, a := range doc.Agents {
		if a.NodeID == 0 {
			continue // 0 is reserved / would silently match unset fields
		}
		idx[a.NodeID] = a.Hostname
	}
	mu.Lock()
	byNode = idx
	all = doc.Agents
	mu.Unlock()
	return nil
}
