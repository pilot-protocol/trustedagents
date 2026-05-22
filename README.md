# trustedagents

Pilot Protocol trusted-agents plugin. Ships an embedded allowlist of
public node IDs that the daemon auto-accepts handshake requests from,
plus a 1-hour refresher loop that pulls the canonical list from this
repo on a schedule.

## Layout

| File | What it does |
|---|---|
| `data.go` | Embedded JSON list. `Load`, `All`, `IsTrusted(nodeID) → (description, ok)`, `SetForTest`. |
| `runtime.go` | `Run(ctx)` — periodic fetcher (HTTPS to `raw.githubusercontent.com`). |
| `service.go` | `*Service` — `coreapi.Service` adapter (`Name/Order/Start/Stop` + `IsTrusted`). Build tag `!no_trustedagents`. |
| `service_disabled.go` | Stub `*Service` when build tag `no_trustedagents` is set. |
| `trusted-agents.json` | The list itself. PRs adding entries land here. |

## Import paths

```go
// data + lookup
import "github.com/pilot-protocol/trustedagents"

ok, name := trustedagents.IsTrusted(nodeID)
```

The daemon's `cmd/daemon/main.go` registers the plugin via:

```go
rt.Register(trustedagents.NewService())
```

## Updating the list

Edit `trusted-agents.json`, open a PR. Once merged, daemons in the
field pick up the new list on their next 1-hour refresh tick. Brand-new
daemons get the embedded copy compiled into the binary.

## Disabling

Pass `-tags no_trustedagents` to `go build` to compile a stub service
that always returns `(""", false)` from `IsTrusted`. Used by integration
tests that need a clean trust state.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4 (the protocol repo) pulls it
in via `require github.com/pilot-protocol/trustedagents v0.1.0`. During
co-development the protocol repo uses `replace ../trustedagents`.
