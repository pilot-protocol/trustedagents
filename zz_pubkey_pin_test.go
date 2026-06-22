// SPDX-License-Identifier: AGPL-3.0-or-later

package trustedagents

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// newPin generates an Ed25519 keypair and returns the public key both as
// raw bytes (for IsTrustedWithKey) and base64 (for the Agent.PublicKey
// field), matching the std-encoding the loader expects.
func newPin(t *testing.T) (raw ed25519.PublicKey, b64 string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, base64.StdEncoding.EncodeToString(pub)
}

// TestIsTrustedWithKey_PinnedCorrectKey: a pinned entry trusts the peer
// when the authenticated key matches the pin.
func TestIsTrustedWithKey_PinnedCorrectKey(t *testing.T) {
	raw, b64 := newPin(t)
	restore := SetForTest([]Agent{
		{Hostname: "pinned-agent", NodeID: 100, PublicKey: b64},
	})
	t.Cleanup(restore)

	name, ok := IsTrustedWithKey(100, raw)
	if !ok || name != "pinned-agent" {
		t.Fatalf("IsTrustedWithKey(100, correct) = (%q,%v), want (pinned-agent,true)", name, ok)
	}
}

// TestIsTrustedWithKey_PinnedWrongKey: a pinned entry refuses a peer
// presenting a different key, even though the node_id matches.
func TestIsTrustedWithKey_PinnedWrongKey(t *testing.T) {
	_, b64 := newPin(t)
	wrong, _ := newPin(t)
	restore := SetForTest([]Agent{
		{Hostname: "pinned-agent", NodeID: 100, PublicKey: b64},
	})
	t.Cleanup(restore)

	if name, ok := IsTrustedWithKey(100, wrong); ok {
		t.Fatalf("IsTrustedWithKey(100, wrong-key) = (%q,true), want untrusted", name)
	}
}

// TestIsTrustedWithKey_PinnedEmptyKey: a pinned entry refuses an empty
// or short presented key — a missing authenticated key cannot satisfy a
// pin.
func TestIsTrustedWithKey_PinnedEmptyKey(t *testing.T) {
	_, b64 := newPin(t)
	restore := SetForTest([]Agent{
		{Hostname: "pinned-agent", NodeID: 100, PublicKey: b64},
	})
	t.Cleanup(restore)

	if _, ok := IsTrustedWithKey(100, nil); ok {
		t.Fatal("IsTrustedWithKey(100, nil) must not trust a pinned entry")
	}
	if _, ok := IsTrustedWithKey(100, []byte{1, 2, 3}); ok {
		t.Fatal("IsTrustedWithKey(100, short) must not trust a pinned entry")
	}
}

// TestIsTrustedWithKey_UnpinnedBackwardCompat: an entry with no
// PublicKey (the state of every entry shipped today) is trusted by
// node_id alone, regardless of the presented key. This preserves
// current production behavior.
func TestIsTrustedWithKey_UnpinnedBackwardCompat(t *testing.T) {
	restore := SetForTest([]Agent{
		{Hostname: "legacy-agent", NodeID: 200}, // no PublicKey
	})
	t.Cleanup(restore)

	// Any key — including a random one — is accepted because the entry
	// is unpinned.
	some, _ := newPin(t)
	if name, ok := IsTrustedWithKey(200, some); !ok || name != "legacy-agent" {
		t.Fatalf("IsTrustedWithKey(200, anykey) = (%q,%v), want (legacy-agent,true)", name, ok)
	}
	// Even a nil key is fine for an unpinned entry.
	if name, ok := IsTrustedWithKey(200, nil); !ok || name != "legacy-agent" {
		t.Fatalf("IsTrustedWithKey(200, nil) = (%q,%v), want (legacy-agent,true)", name, ok)
	}
}

// TestIsTrustedWithKey_UnknownNode: a node_id not on the list is never
// trusted, with or without a key.
func TestIsTrustedWithKey_UnknownNode(t *testing.T) {
	restore := SetForTest([]Agent{
		{Hostname: "known", NodeID: 200},
	})
	t.Cleanup(restore)

	some, _ := newPin(t)
	if _, ok := IsTrustedWithKey(999, some); ok {
		t.Fatal("IsTrustedWithKey(999, ...) must not trust an unknown node")
	}
}

// TestIsTrusted_UnchangedByPin: the existing key-less IsTrusted keeps
// working for both pinned and unpinned entries — it answers the
// node_id-only question and does not consult the pin.
func TestIsTrusted_UnchangedByPin(t *testing.T) {
	_, b64 := newPin(t)
	restore := SetForTest([]Agent{
		{Hostname: "pinned-agent", NodeID: 100, PublicKey: b64},
		{Hostname: "legacy-agent", NodeID: 200},
	})
	t.Cleanup(restore)

	if name, ok := IsTrusted(100); !ok || name != "pinned-agent" {
		t.Fatalf("IsTrusted(100) = (%q,%v), want (pinned-agent,true)", name, ok)
	}
	if name, ok := IsTrusted(200); !ok || name != "legacy-agent" {
		t.Fatalf("IsTrusted(200) = (%q,%v), want (legacy-agent,true)", name, ok)
	}
	if _, ok := IsTrusted(999); ok {
		t.Fatal("IsTrusted(999): unknown node must not match")
	}
}

// TestLoad_PinnedEntry: a public_key in the JSON round-trips through
// Load into an enforced pin.
func TestLoad_PinnedEntry(t *testing.T) {
	restore := SetForTest(nil)
	t.Cleanup(restore)

	raw, b64 := newPin(t)
	doc := []byte(`{"agents":[{"hostname":"x","node_id":1,"public_key":"` + b64 + `"}]}`)
	if err := Load(doc); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := IsTrustedWithKey(1, raw); !ok {
		t.Fatal("loaded pinned entry: correct key should be trusted")
	}
	wrong, _ := newPin(t)
	if _, ok := IsTrustedWithKey(1, wrong); ok {
		t.Fatal("loaded pinned entry: wrong key must not be trusted")
	}
}

// TestLoad_BadPinRejected: a malformed public_key fails the whole Load
// rather than silently degrading the entry to unpinned (which would
// re-open finding H4 for that agent).
func TestLoad_BadPinRejected(t *testing.T) {
	restore := SetForTest(nil)
	t.Cleanup(restore)

	// Not valid base64.
	if err := Load([]byte(`{"agents":[{"hostname":"x","node_id":1,"public_key":"!!!not-base64!!!"}]}`)); err == nil {
		t.Error("Load must reject a non-base64 public_key")
	}
	// Valid base64 but wrong length for an Ed25519 key.
	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if err := Load([]byte(`{"agents":[{"hostname":"x","node_id":1,"public_key":"` + short + `"}]}`)); err == nil {
		t.Error("Load must reject a wrong-length public_key")
	}
}

// TestService_IsTrustedWithKey_Delegates exercises the Service adapter
// method end-to-end.
func TestService_IsTrustedWithKey_Delegates(t *testing.T) {
	raw, b64 := newPin(t)
	restore := SetForTest([]Agent{
		{Hostname: "svc-agent", NodeID: 100, PublicKey: b64},
	})
	t.Cleanup(restore)

	s := NewService()
	if name, ok := s.IsTrustedWithKey(100, raw); !ok || name != "svc-agent" {
		t.Fatalf("Service.IsTrustedWithKey(100, correct) = (%q,%v), want (svc-agent,true)", name, ok)
	}
	wrong, _ := newPin(t)
	if _, ok := s.IsTrustedWithKey(100, wrong); ok {
		t.Fatal("Service.IsTrustedWithKey(100, wrong) must be untrusted")
	}
}
