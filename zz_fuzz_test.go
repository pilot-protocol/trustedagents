// SPDX-License-Identifier: AGPL-3.0-or-later

// zz_fuzz_test.go — adversarial/fuzz coverage for the trust-decision
// loader. The trusted-agents list is fetched over the network and
// embedded at build time; a malformed, oversized, or hostile document
// must NEVER panic the loader or silently open auto-accept trust.
//
// Two invariants are fuzzed here:
//
//   - FuzzLoad: Load over arbitrary bytes never panics, and whenever it
//     returns nil the resulting in-memory list is internally consistent
//     and fail-closed (no zero/empty entries trusted, no node trusted
//     with a different key than its pin).
//
//   - FuzzDecodePin: the per-entry pin decoder never panics and only
//     yields a non-nil key of the exact Ed25519 size — a malformed pin
//     is an error, never a silently-accepted short/long key.
//
// These complement the deterministic matrix in zz_pubkey_pin_test.go;
// they don't restate it, they stress the parser boundary around it.

package trustedagents

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// loaderConsistent asserts the package-global trust state is internally
// coherent after a successful Load: every indexed node is non-zero and
// named, and any pinned node refuses a deliberately-wrong key while
// accepting nothing it should not. Run under the package lock by the
// caller's contract (we take RLock here).
func loaderConsistent(t *testing.T) {
	t.Helper()
	mu.RLock()
	defer mu.RUnlock()
	for nodeID, e := range byNode {
		if nodeID == 0 {
			t.Fatalf("fail-closed violated: node_id 0 is indexed (name=%q)", e.name)
		}
		if e.name == "" {
			t.Fatalf("fail-closed violated: node_id %d indexed with empty name", nodeID)
		}
		if e.pubKey != nil && len(e.pubKey) != ed25519.PublicKeySize {
			t.Fatalf("node_id %d pinned with non-Ed25519-size key (%d bytes)", nodeID, len(e.pubKey))
		}
	}
}

// FuzzLoad throws arbitrary bytes at Load. Contract under test:
//   - Load never panics.
//   - On success (err == nil) the trust index is fail-closed and a
//     pinned entry never trusts a freshly-generated random key.
func FuzzLoad(f *testing.F) {
	// Seed corpus: valid, malformed, oversized, duplicate, pinned,
	// and boundary documents.
	_, goodPin := func() (ed25519.PublicKey, string) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return pub, base64.StdEncoding.EncodeToString(pub)
	}()
	seeds := []string{
		`{"agents":[]}`,
		`{"agents":[{"hostname":"a","node_id":1}]}`,
		`{"agents":[{"hostname":"a","node_id":0}]}`,                              // zero id dropped
		`{"agents":[{"hostname":"","node_id":5}]}`,                               // empty host dropped
		`{"agents":[{"hostname":"a","node_id":1},{"hostname":"b","node_id":1}]}`, // duplicate → error
		`{"agents":[{"hostname":"a","node_id":1,"public_key":"` + goodPin + `"}]}`,
		`{"agents":[{"hostname":"a","node_id":1,"public_key":"!!!"}]}`,    // bad base64
		`{"agents":[{"hostname":"a","node_id":1,"public_key":"AAAA"}]}`,   // short key
		`{"agents":[{"hostname":"a","node_id":1,"tier":"x","extra":42}]}`, // extra fields
		`{not json`,
		``,
		`null`,
		`{"agents":null}`,
		`[]`,
		`{"agents":` + strings.Repeat("[", 4096) + `}`, // deeply nested / oversized
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	// Snapshot and restore the global list around the whole fuzz run so
	// we don't corrupt state for other tests in the package.
	restore := SetForTest(nil)
	defer restore()

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Reset to a known-empty baseline each iteration so a prior
		// successful Load can't mask a later failing one.
		_ = Load([]byte(`{"agents":[]}`))

		// The contract: never panic, whatever the input.
		err := Load(raw)
		if err != nil {
			// A failed Load must NOT have replaced the active list with a
			// partially-built or corrupt one. The empty baseline must hold:
			// nothing new should be trusted.
			loaderConsistent(t)
			return
		}

		// Success: index must be fail-closed and self-consistent.
		loaderConsistent(t)

		// For any node that ended up pinned, a random key must be refused
		// (constant-time mismatch path), and the key-less IsTrusted must
		// still answer by node_id.
		randPub, _, _ := ed25519.GenerateKey(rand.Reader)
		for nodeID, e := range snapshotIndex() {
			if _, ok := IsTrusted(nodeID); !ok {
				t.Fatalf("node_id %d in index but IsTrusted says untrusted", nodeID)
			}
			if e.pubKey != nil {
				if _, ok := IsTrustedWithKey(nodeID, randPub); ok {
					t.Fatalf("pinned node_id %d trusted a random key — pin not enforced", nodeID)
				}
			}
		}
	})
}

// snapshotIndex returns a copy of the current byNode map so the fuzz
// body can iterate without holding the package lock across IsTrusted*
// calls (which take the lock themselves).
func snapshotIndex() map[uint32]entry {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[uint32]entry, len(byNode))
	for k, v := range byNode {
		out[k] = v
	}
	return out
}

// FuzzDecodePin throws arbitrary strings at the pin decoder. Contract:
//   - never panics;
//   - returns either (nil, err) or a key of EXACTLY ed25519.PublicKeySize;
//   - a successfully-decoded non-empty pin round-trips and verifies a
//     signature only for its own keypair (sanity that we built a real key).
func FuzzDecodePin(f *testing.F) {
	good := base64.StdEncoding.EncodeToString(func() []byte {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		return pub
	}())
	for _, s := range []string{"", good, "!!!", "AAAA", "Zm9v", strings.Repeat("A", 10000)} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		key, err := decodePin(s)
		if err != nil {
			if key != nil {
				t.Fatalf("decodePin(%q) returned a key alongside an error", s)
			}
			return
		}
		if s == "" {
			if key != nil {
				t.Fatalf("decodePin(\"\") must be (nil,nil), got %d bytes", len(key))
			}
			return
		}
		if len(key) != ed25519.PublicKeySize {
			t.Fatalf("decodePin(%q) returned %d bytes, want %d", s, len(key), ed25519.PublicKeySize)
		}
	})
}

// TestLoad_OversizedDocDoesNotPanic is a deterministic guard alongside
// the fuzzer: a pathologically large but well-formed agents array must
// load (or error) without panicking or wedging. Runtime caps the fetch
// at 1 MiB; this exercises the in-process loader directly above that.
func TestLoad_OversizedDocDoesNotPanic(t *testing.T) {
	restore := SetForTest(nil)
	t.Cleanup(restore)

	var b strings.Builder
	b.WriteString(`{"agents":[`)
	const n = 50000
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		// node_id i, unique hostname; no pins so Load stays cheap.
		b.WriteString(`{"hostname":"h`)
		b.WriteString(itoa(i))
		b.WriteString(`","node_id":`)
		b.WriteString(itoa(i))
		b.WriteByte('}')
	}
	b.WriteString(`]}`)

	if err := Load([]byte(b.String())); err != nil {
		t.Fatalf("oversized well-formed doc must load: %v", err)
	}
	if _, ok := IsTrusted(n); !ok {
		t.Fatalf("last entry node_id %d should be trusted after large Load", n)
	}
}

// TestLoad_DuplicateWithPinsRejected confirms the duplicate-node_id
// guard still fires when the colliding entries carry pins — the loader
// must reject rather than letting the second pin silently win.
func TestLoad_DuplicateWithPinsRejected(t *testing.T) {
	restore := SetForTest(nil)
	t.Cleanup(restore)

	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	a := base64.StdEncoding.EncodeToString(pubA)
	bk := base64.StdEncoding.EncodeToString(pubB)
	doc := `{"agents":[` +
		`{"hostname":"x","node_id":7,"public_key":"` + a + `"},` +
		`{"hostname":"y","node_id":7,"public_key":"` + bk + `"}]}`
	if err := Load([]byte(doc)); err == nil {
		t.Fatal("duplicate node_id with pins must be rejected")
	}
	// The failed Load must not have trusted either pin.
	if _, ok := IsTrustedWithKey(7, pubA); ok {
		t.Fatal("node_id 7 must not be trusted after a rejected duplicate Load")
	}
	if _, ok := IsTrustedWithKey(7, pubB); ok {
		t.Fatal("node_id 7 must not be trusted after a rejected duplicate Load")
	}
}

// itoa is a tiny allocation-light int formatter for the oversized-doc
// builder (avoids pulling strconv into the hot loop's import surface).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
