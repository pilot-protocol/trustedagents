// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_trustedagents
// +build !no_trustedagents

// zz_fetch_test.go — exercises runtime.go's fetchOnce + Run loop. The
// defaultURL is a const we cannot redirect, so we inject an
// http.RoundTripper into the client that rewrites requests pointed at
// raw.githubusercontent.com to a local httptest server. The transport
// is the only seam available without refactoring source files.
//
// Iter-1 audit (HIGH) flagged: no signature verification on
// runtime-fetched allowlist. TestFetchOnce_AcceptsAnyJSON_NoSignatureCheck
// pins that behaviour so any future signature work breaks the test and
// forces a deliberate update.

package trustedagents

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
)

// rewriteTransport routes any request to host raw.githubusercontent.com
// at the provided test server URL while preserving method/headers. This
// is the seam fetchOnce gives us — it accepts a *http.Client, and
// http.Client honours the Transport's RoundTrip behaviour.
type rewriteTransport struct {
	target *url.URL
	calls  int32 // atomic — how many times RoundTrip ran
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&r.calls, 1)
	// Mutate a clone so we don't surprise the caller.
	clone := req.Clone(req.Context())
	clone.URL.Scheme = r.target.Scheme
	clone.URL.Host = r.target.Host
	clone.Host = r.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func newRewriteClient(srv *httptest.Server) (*http.Client, *rewriteTransport) {
	u, _ := url.Parse(srv.URL)
	rt := &rewriteTransport{target: u}
	return &http.Client{Transport: rt, Timeout: 5 * time.Second}, rt
}

// TestFetchOnce_Success drives the full happy path: 200 + valid JSON
// body. After the call Load() must have populated the global list.
func TestFetchOnce_Success(t *testing.T) {
	// Mutates package state via Load — no t.Parallel.
	restore := SetForTest(nil)
	t.Cleanup(restore)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Confirm fetchOnce attached the documented UA.
		if got := req.Header.Get("User-Agent"); got != "pilot-daemon/trustedagents" {
			t.Errorf("User-Agent = %q, want pilot-daemon/trustedagents", got)
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"agents":[
			{"hostname":"injected","address":"0:0:1","node_id":4242}
		]}`)
	}))
	defer srv.Close()

	client, rt := newRewriteClient(srv)
	if err := fetchOnce(context.Background(), client); err != nil {
		t.Fatalf("fetchOnce: %v", err)
	}
	if atomic.LoadInt32(&rt.calls) != 1 {
		t.Errorf("RoundTrip calls = %d, want 1", rt.calls)
	}
	if name, ok := IsTrusted(4242); !ok || name != "injected" {
		t.Errorf("after fetch IsTrusted(4242) = (%q,%v), want (injected,true)", name, ok)
	}
}

// TestFetchOnce_AcceptsUnsignedJSON_BackwardCompat verifies that an
// unsigned trusted-agents list (no "signature" field) is still accepted
// when the embedded public key is the zero placeholder. This preserves
// backward compatibility until the operator deploys signing.
func TestFetchOnce_AcceptsUnsignedJSON_BackwardCompat(t *testing.T) {
	restore := SetForTest(nil)
	t.Cleanup(restore)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"agents":[
			{"hostname":"unsigned-peer","node_id":1}
		]}`)
	}))
	defer srv.Close()

	client, _ := newRewriteClient(srv)
	if err := fetchOnce(context.Background(), client); err != nil {
		t.Fatalf("fetchOnce with unsigned JSON: %v", err)
	}
	if _, ok := IsTrusted(1); !ok {
		t.Fatal("unsigned JSON should still be accepted (backward compat)")
	}
}

// TestVerifyAndStripSig_UnsignedIsOK confirms VerifyAndStripSig returns the
// raw body unchanged when no signature field is present.
func TestVerifyAndStripSig_UnsignedIsOK(t *testing.T) {
	raw := []byte(`{"agents":[{"hostname":"x","node_id":7}]}`)
	out, err := VerifyAndStripSig(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != string(raw) {
		t.Errorf("output differs from input on unsigned payload")
	}
}

// TestVerifyAndStripSig_BadSignatureIsRejected confirms that a payload
// with an invalid signature is rejected.
func TestVerifyAndStripSig_BadSignatureIsRejected(t *testing.T) {
	// Temporarily set a non-zero pubkey so verification runs.
	prevKey := make(ed25519.PublicKey, 32)
	copy(prevKey, embeddedPubKey)
	t.Cleanup(func() { copy(embeddedPubKey, prevKey) })
	for i := range embeddedPubKey {
		embeddedPubKey[i] = 0xFF
	}

	raw := []byte(`{"agents":[{"hostname":"bad","node_id":9}],"signature":"aW52YWxpZCBzaWduYXR1cmUgZm9yIHRlc3Rpbmc="}`)
	_, err := VerifyAndStripSig(raw)
	if err == nil {
		t.Fatal("expected signature mismatch error")
	}
	if !strings.Contains(err.Error(), "signature mismatch") &&
		!strings.Contains(err.Error(), "signature") {
		t.Errorf("err = %v, want signature-related", err)
	}
}

// TestVerifyAndStripSig_SignaturePresentButKeyNotConfigured confirms that
// a payload WITH a signature is rejected when embeddedPubKey is zero.
func TestVerifyAndStripSig_SignaturePresentButKeyNotConfigured(t *testing.T) {
	raw := []byte(`{"agents":[{"hostname":"x","node_id":3}],"signature":"AAAA"}`)
	_, err := VerifyAndStripSig(raw)
	if err == nil {
		t.Fatal("expected error: signature present but key not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("err = %v, want 'not configured'", err)
	}
}

// TestVerifyAndStripSig_ValidSignatureIsAccepted verifies end-to-end:
// sign a payload with a fresh key, embed the public key, and assert the
// verification succeeds.
func TestVerifyAndStripSig_ValidSignatureIsAccepted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Temporarily install the fresh public key.
	prevKey := make(ed25519.PublicKey, 32)
	copy(prevKey, embeddedPubKey)
	t.Cleanup(func() { copy(embeddedPubKey, prevKey) })
	copy(embeddedPubKey, pub)

	// Build the canonical payload that the signer would produce.
	type envelope struct {
		Agents    json.RawMessage `json:"agents"`
		Signature *string         `json:"signature,omitempty"`
	}
	env := envelope{
		Agents: json.RawMessage(`[{"hostname":"ok","node_id":42}]`),
	}
	payload, _ := json.Marshal(env)
	sig := ed25519.Sign(priv, payload)
	sigStr := base64.StdEncoding.EncodeToString(sig)
	env.Signature = &sigStr
	signed, _ := json.Marshal(env)

	out, err := VerifyAndStripSig(signed)
	if err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Output should be the same canonical form (without signature).
	if !strings.Contains(string(out), `"node_id":42`) {
		t.Errorf("output missing expected agent: %s", out)
	}
	if strings.Contains(string(out), `"signature"`) {
		t.Error("output should not contain signature field")
	}
}

// TestFetchOnce_BadStatus drives the resp.StatusCode != 200 branch.
func TestFetchOnce_BadStatusDriven(t *testing.T) {
	// Mutates package state via fetchMu — no t.Parallel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	client, _ := newRewriteClient(srv)
	err := fetchOnce(context.Background(), client)
	if err == nil {
		t.Fatal("expected error from 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("err = %v, want one mentioning 503", err)
	}
}

// TestFetchOnce_BodyIsBadJSON drives Load's error wrap in fetchOnce.
func TestFetchOnce_BodyIsBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{this is not json`)
	}))
	defer srv.Close()

	client, _ := newRewriteClient(srv)
	err := fetchOnce(context.Background(), client)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
	if !strings.Contains(err.Error(), "verify:") {
		t.Errorf("err = %v, want 'verify:' prefix from fetchOnce wrap", err)
	}
}

// errTransport is a RoundTripper that always returns an error — drives
// the client.Do(req) error branch in fetchOnce.
type errTransport struct{ err error }

func (e *errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

func TestFetchOnce_TransportError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("simulated transport failure")
	client := &http.Client{Transport: &errTransport{err: wantErr}}
	err := fetchOnce(context.Background(), client)
	if err == nil {
		t.Fatal("expected transport error to propagate")
	}
	// http.Client wraps transport errors in url.Error — check substring.
	if !strings.Contains(err.Error(), "simulated transport failure") {
		t.Errorf("err = %v, want one mentioning the simulated failure", err)
	}
}

// TestFetchOnce_BadURLRequest covers the http.NewRequestWithContext
// error branch. The only way to provoke it is via a nil context — but
// NewRequestWithContext panics on nil ctx. Instead, drive a request
// with a control character that the URL parser rejects... but
// defaultURL is a const we can't change. Document and skip.
//
// We can however drive ctx-cancel-during-fetch which exercises the
// client.Do error path with a more realistic shape.
func TestFetchOnce_ContextCancelled(t *testing.T) {
	// Server hangs until the test releases it. Defer order matters:
	// close(block) MUST run before srv.Close(), so the handler unblocks
	// and srv.Close()'s active-conn wait can drain. Defers fire LIFO,
	// so register srv.Close() first, close(block) last.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer srv.Close()
	defer close(block)

	client, _ := newRewriteClient(srv)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := fetchOnce(ctx, client)
	if err == nil {
		t.Fatal("expected context-cancelled error")
	}
}

// shortReadBody returns N bytes then an error — drives io.ReadAll's
// error branch inside fetchOnce. We wire it via a custom transport.
type shortReadBody struct{ remaining int }

func (b *shortReadBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, fmt.Errorf("synthetic read failure")
	}
	n := len(p)
	if n > b.remaining {
		n = b.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = '{'
	}
	b.remaining -= n
	return n, nil
}

func (b *shortReadBody) Close() error { return nil }

type fixedRespTransport struct{ resp *http.Response }

func (f *fixedRespTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.resp.Request = req
	return f.resp, nil
}

func TestFetchOnce_BodyReadError(t *testing.T) {
	t.Parallel()
	resp := &http.Response{
		StatusCode: 200,
		Body:       &shortReadBody{remaining: 3},
		Header:     make(http.Header),
	}
	client := &http.Client{Transport: &fixedRespTransport{resp: resp}}
	err := fetchOnce(context.Background(), client)
	if err == nil {
		t.Fatal("expected body read error")
	}
	if !strings.Contains(err.Error(), "synthetic read failure") {
		t.Errorf("err = %v, want synthetic read failure", err)
	}
}

// TestFetchOnce_LimitsBodyTo1MiB confirms the io.LimitReader cap. We
// serve 2 MiB of '{' chars; the cap means io.ReadAll returns at most
// 1 MiB, and Load will then fail on truncated JSON.
func TestFetchOnce_LimitsBodyTo1MiB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "2097152")
		w.WriteHeader(200)
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = '{'
		}
		// 2 MiB total — exceeds the 1 MiB cap.
		for i := 0; i < 512; i++ {
			_, _ = w.Write(buf)
		}
	}))
	defer srv.Close()

	client, _ := newRewriteClient(srv)
	err := fetchOnce(context.Background(), client)
	if err == nil {
		t.Fatal("expected JSON parse error after 1 MiB cap")
	}
}

// TestRun_FullIteration drives Run through one full select-timer ->
// fetchOnce -> timer.Reset cycle, then exits via ctx cancel. We need
// fetchInterval-grade timing not to wait the real hour, so we can't
// reach Reset's "long" path — but the first Reset triggers regardless,
// covering both 'case <-timer.C' arms.
func TestRun_FullIteration(t *testing.T) {
	// Mutates package state via Load — no t.Parallel.
	restore := SetForTest(nil)
	t.Cleanup(restore)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"agents":[{"hostname":"r","node_id":777}]}`)
	}))
	defer srv.Close()

	// Run uses its own internal client; we can't inject one. But Run is
	// 5 lines — for coverage we just need to drive the goroutine through
	// at least one timer tick or the ctx-done branch. Cancel ctx
	// immediately to drive the ctx-done branch in the select.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
}

// TestRun_TimerFires drives Run through the timer.C → fetchOnce →
// timer.Reset arm. We shrink initialJitterMax to 0 so the first timer
// fires immediately, and inject a failing http client so fetchOnce
// returns an error and the slog.Warn branch is also covered.
func TestRun_TimerFires(t *testing.T) {
	// Mutates package state — no t.Parallel.
	prevJ := initialJitterMax
	initialJitterMax = 0
	t.Cleanup(func() { initialJitterMax = prevJ })

	prevClient := httpClientForRun
	httpClientForRun = func() *http.Client {
		return &http.Client{Transport: &errTransport{err: errors.New("injected: no network")}}
	}
	t.Cleanup(func() { httpClientForRun = prevClient })

	restore := SetForTest(nil)
	t.Cleanup(restore)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx)
		close(done)
	}()
	// Give Run enough time to fire the timer once + log + reset.
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after timer-fired path + cancel")
	}
}

// TestRun_FetchPath drives Run through the timer.C -> fetchOnce ->
// timer.Reset arm. We can't shrink fetchInterval (const), so we can't
// drive a second iteration in test time. But the first iteration —
// jitter(30s) — can fire if we cancel exactly when the timer.C arm
// has been entered. That's racy, so instead we cancel ctx after a
// shorter sleep and rely on the goroutine eventually returning. The
// goal is the timer.Stop defer and select-on-ctx-done branches.
func TestRun_CancelMidWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx)
		close(done)
	}()
	// Let Run enter the select with the jittered timer pending.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after mid-wait cancel")
	}
}

// TestService_Stop_CtxDoneBranch drives Stop's ctx-done arm by
// installing a Service whose internal Run goroutine never exits within
// the Stop deadline. We simulate that by manually starting the Service
// — Run's loop holds until ctx cancels — then calling Stop with a
// pre-cancelled context to force the `case <-ctx.Done()` branch.
func TestService_Stop_CtxDoneBranch(t *testing.T) {
	// Mutates package state — no t.Parallel.
	s := NewService()
	// Start so s.cancel and s.done are set.
	if err := s.Start(context.Background(), depsForTest()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Don't cancel the runCtx — Run goroutine stays alive. Then Stop
	// with a pre-cancelled ctx: Stop calls cancel() (which would let
	// the goroutine exit) but the racy nature is real. To deterministically
	// hit the ctx.Done branch we Stop with an already-expired ctx; the
	// select picks whichever's ready. We give the runner a moment to
	// react; if it exits first the test still passes (Stop returns nil),
	// otherwise Stop returns ctx.Err() — both arms acceptable.
	stopCtx, stopCancel := context.WithCancel(context.Background())
	stopCancel() // pre-cancelled
	err := s.Stop(stopCtx)
	// Either outcome is valid; this test exists to drive both select arms.
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("Stop: unexpected err %v", err)
	}
	// Always allow the goroutine to finish so we don't leak.
	_ = s.Stop(context.Background())
}

// depsForTest builds a coreapi.Deps zero-value. The struct's only
// reference we touch is Events (nil-safe via RecoverPlugin).
func depsForTest() coreapi.Deps { return coreapi.Deps{} }
