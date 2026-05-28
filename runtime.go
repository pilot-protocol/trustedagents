// SPDX-License-Identifier: AGPL-3.0-or-later

// runtime.go — the periodic-refresh side of the trustedagents package.
// Run() polls the canonical URL on the project repo for an updated
// list, falling back to the embedded JSON in data.go on failure.

package trustedagents

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	defaultURL    = "https://raw.githubusercontent.com/pilot-protocol/trustedagents/main/trusted-agents.json"
	fetchInterval = 1 * time.Hour
)

// fetchMu serialises HTTP refreshers when multiple plugin services
// happen to share a process (e.g. tests).
var fetchMu sync.Mutex

// initialJitterMax controls the first-fetch jitter window. Exposed as a
// var (not a const) so tests can shorten it to 0 and deterministically
// drive Run through one full timer.C → fetchOnce → timer.Reset cycle.
var initialJitterMax = 30 * time.Second

// httpClientForRun is the http.Client Run uses. Exposed as a var so
// tests can inject a transport that returns a deterministic error,
// covering the slog.Warn-on-fetch-fail branch without depending on the
// real network.
var httpClientForRun = func() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// Run polls the canonical URL on a timer, replacing the active list
// whenever a new one is fetched. Blocks until ctx is cancelled. The
// first fetch is delayed 0–30s so a fleet rebooting at the same time
// doesn't thunder the URL.
func Run(ctx context.Context) {
	client := httpClientForRun()
	timer := time.NewTimer(jitter(initialJitterMax))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := fetchOnce(ctx, client); err != nil {
			slog.Warn("trustedagents fetch failed", "err", err)
		}
		timer.Reset(fetchInterval + jitter(fetchInterval/10))
	}
}

func fetchOnce(ctx context.Context, client *http.Client) error {
	fetchMu.Lock()
	defer fetchMu.Unlock()
	// http.NewRequestWithContext only fails on an invalid method or URL —
	// both are compile-time constants here, so the error is unreachable.
	req, _ := http.NewRequestWithContext(ctx, "GET", defaultURL, nil)
	req.Header.Set("User-Agent", "pilot-daemon/trustedagents")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return err
	}
	// Verify ed25519 signature (if present) before trusting the list.
	// On absent/mismatched signature, return error → Run falls back to
	// the embedded list.
	verified, err := VerifyAndStripSig(body)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if err := Load(verified); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	slog.Info("trustedagents list fetched", "agents", len(All()))
	return nil
}

func jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max / 2
	}
	return time.Duration(n.Int64())
}
