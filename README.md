# trustedagents

[![ci](https://github.com/pilot-protocol/trustedagents/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/trustedagents/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/trustedagents/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/trustedagents)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

Trusted-agents plugin for the Pilot Protocol daemon. Ships an embedded
allowlist of public node IDs that the daemon auto-accepts handshake
requests from, plus a 1-hour refresher loop that pulls the canonical
list from this repo on a schedule.

## Install

```go
import "github.com/pilot-protocol/trustedagents"
```

## Usage

```go
// Lookup:
name, ok := trustedagents.IsTrusted(nodeID)
_ = name
_ = ok

// Daemon registration:
rt.Register(trustedagents.NewService())
```

## Layout

| File | What it does |
|---|---|
| `data.go` | Embedded JSON list. `Load`, `All`, `IsTrusted(nodeID) → (description, ok)`, `SetForTest`. |
| `runtime.go` | `Run(ctx)` — periodic fetcher over HTTPS to `raw.githubusercontent.com`. |
| `service.go` | `*Service` — `coreapi.Service` adapter (`Name/Order/Start/Stop` + `IsTrusted`). Build tag `!no_trustedagents`. |
| `service_disabled.go` | Stub `*Service` when build tag `no_trustedagents` is set. |
| `trusted-agents.json` | The list itself. PRs adding entries land here. |

## Updating the list

Edit `trusted-agents.json` and open a PR. Once merged, daemons in the
field pick up the new list on their next 1-hour refresh tick. Brand-new
daemons get the embedded copy compiled into the binary.

## Build tags

| Tag | Effect |
|---|---|
| `no_trustedagents` | Compiles a stub that always returns `("", false)` from `IsTrusted`. Used by integration tests that need a clean trust state. |

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
