// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_trustedagents
// +build !no_trustedagents

package trustedagents

import "testing"

// TestService_IsTrustedWithKey_Delegates exercises the enabled Service
// adapter end-to-end. The no_trustedagents build has its own fail-closed
// service contract.
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
