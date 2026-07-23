// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trustedagents holds the build-time-embedded list of node IDs
// that the daemon auto-accepts handshake requests from. The data layer
// is utility-tier so both the daemon plugin (plugins/trustedagents)
// and the CLI (cmd/pilotctl) can read it without violating the strict
// downward layer rule.
//
// The list is plain JSON in this directory, embedded at build time and
// refreshed hourly from raw.githubusercontent.com by
// plugins/trustedagents.Run. Authenticity is handled in two tiers:
// unsigned lists are accepted over TLS with a warning (backward-compatible);
// signed lists require embeddedPubKey to be configured and undergo full
// Ed25519 verification via VerifyAndStripSig before the payload is trusted.
//
// Adding an agent: edit trusted-agents.json, commit. Daemons in the
// field pick it up within ~1h. Brand-new daemons get the embedded copy
// from the binary, so the feature works on first boot even airgapped.
package trustedagents

import (
	"crypto/ed25519"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
)

// Agent is one entry in the trusted-agents list. Match is by NodeID;
// Hostname and Address are kept for logs and `pilotctl trusted list`.
// Other JSON fields in the source file (tier, description, ...) are
// silently ignored on unmarshal — we don't care about them at runtime.
//
// PublicKey is OPTIONAL: a base64 (std encoding) Ed25519 public key
// pinning the node_id to a specific key. When present, the inbound
// auto-accept path MUST verify the authenticated peer's key equals it
// (see IsTrustedWithKey). When absent — as for every entry shipped
// today — trust falls back to node_id alone, preserving current
// behavior. Pinning closes audit finding H4: without it, taking over a
// trusted node_id (or a registry that maps a trusted node_id to an
// attacker key) inherits full auto-approve trust.
type Agent struct {
	Hostname  string `json:"hostname"`
	Address   string `json:"address"`
	NodeID    uint32 `json:"node_id"`
	PublicKey string `json:"public_key,omitempty"`
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

// entry is the in-memory form of a trusted agent: the display name plus
// the optional decoded Ed25519 pin. pubKey is nil when the source entry
// had no public_key (the unpinned, node_id-only case).
type entry struct {
	name   string
	pubKey ed25519.PublicKey // nil == unpinned
}

var (
	mu     sync.RWMutex
	byNode map[uint32]entry // node_id -> entry
	all    []Agent
)

// decodePin parses an Agent.PublicKey field into an ed25519.PublicKey.
// Empty string → (nil, nil): unpinned, not an error. A non-empty value
// that is not valid base64 or not 32 bytes is an error so a malformed
// pin fails the whole Load rather than silently degrading to unpinned.
func decodePin(b64 string) (ed25519.PublicKey, error) {
	if b64 == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("public_key: bad base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public_key: want %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func init() {
	if err := Load(embeddedJSON); err != nil {
		// CI guards this via TestEmbeddedListLoads; if it ever fires in
		// production, an empty list (zero auto-accepts) is the safe default.
		slog.Error("trustedagents: embedded list malformed", "err", err)
		mu.Lock()
		byNode = map[uint32]entry{}
		mu.Unlock()
	}
}

// IsTrusted reports whether nodeID is in the trusted-agents list. The
// caller MUST verify the (node_id, public_key) binding at the registry
// before acting on a true result — this package only checks the list.
//
// IsTrusted does NOT consult the optional per-entry pubkey pin: it
// answers the node_id-only question for callers that have no
// authenticated key in scope. Callers that DO have the authenticated
// peer key (e.g. the inbound handshake auto-accept path) MUST prefer
// IsTrustedWithKey so a present pin is enforced.
func IsTrusted(nodeID uint32) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byNode[nodeID]
	if !ok {
		return "", false
	}
	return e.name, true
}

// IsTrustedWithKey reports whether nodeID is trusted given the
// authenticated peer's Ed25519 public key.
//
//   - nodeID not in the list            → ("", false)
//   - entry HAS a pinned PublicKey       → trusted ONLY if pubKey equals
//     the pin (constant-time compare). A mismatch — or an empty/short
//     pubKey when a pin is required — is ("", false).
//   - entry has NO pin (every entry today) → trusted by node_id alone,
//     preserving IsTrusted's behavior. The unpinned match is logged at
//     debug so finding-H4 exposure is observable until pins are added.
//
// Pass the AUTHENTICATED key (the one the peer proved possession of in
// the handshake), never an unverified claim — otherwise the pin adds
// nothing.
func IsTrustedWithKey(nodeID uint32, pubKey []byte) (string, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := byNode[nodeID]
	if !ok {
		return "", false
	}
	if e.pubKey == nil {
		// Unpinned: backward-compatible node_id-only trust.
		slog.Debug("trustedagents: trusting unpinned entry by node_id only",
			"node_id", nodeID, "agent", e.name)
		return e.name, true
	}
	// Pinned: require an exact, constant-time key match.
	if subtle.ConstantTimeCompare(e.pubKey, pubKey) != 1 {
		slog.Warn("trustedagents: pubkey pin mismatch — refusing auto-accept",
			"node_id", nodeID, "agent", e.name)
		return "", false
	}
	return e.name, true
}

// SetForTest replaces the active list with agents and returns a restore
// function that reloads the embedded list. Test-only — never call from
// production code.
func SetForTest(agents []Agent) (restore func()) {
	idx := make(map[uint32]entry, len(agents))
	for _, a := range agents {
		if a.NodeID == 0 {
			continue
		}
		if a.Hostname == "" {
			continue
		}
		if other, exists := idx[a.NodeID]; exists {
			panic(fmt.Sprintf("SetForTest: duplicate node_id %d (hostnames %q and %q)", a.NodeID, other, a.Hostname))
		}
		pin, err := decodePin(a.PublicKey)
		if err != nil {
			panic(fmt.Sprintf("SetForTest: node_id %d (%q): %v", a.NodeID, a.Hostname, err))
		}
		idx[a.NodeID] = entry{name: a.Hostname, pubKey: pin}
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
// To inject: go build -ldflags "-X github.com/pilot-protocol/trustedagents.embeddedPubKeyHex=<64-hex-chars>"
// Generate keypair: scripts/gen-signing-key.sh
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
	idx := make(map[uint32]entry, len(doc.Agents))
	voided := make(map[uint32]bool) // node_ids seen more than once
	for _, a := range doc.Agents {
		if a.NodeID == 0 {
			continue // 0 is reserved / would silently match unset fields
		}
		if a.Hostname == "" {
			continue // empty hostname: missing required field — drop
		}
		if voided[a.NodeID] {
			continue // a duplicate already voided this node_id (below)
		}
		if other, exists := idx[a.NodeID]; exists {
			// Duplicate node_id: drop EVERY entry for it (the one already
			// indexed and this one) rather than failing the whole list. An
			// ambiguous node_id must not be trusted — neither the first
			// entry nor a later pin may silently win — but a single bad row
			// must not disable the entire feed.
			slog.Warn("trustedagents: duplicate node_id — dropping all entries for it",
				"node_id", a.NodeID, "hostnames", []string{other.name, a.Hostname})
			delete(idx, a.NodeID)
			voided[a.NodeID] = true
			continue
		}
		pin, err := decodePin(a.PublicKey)
		if err != nil {
			return fmt.Errorf("node_id %d (%q): %w", a.NodeID, a.Hostname, err)
		}
		idx[a.NodeID] = entry{name: a.Hostname, pubKey: pin}
	}
	mu.Lock()
	byNode = idx
	all = doc.Agents
	mu.Unlock()
	return nil
}
