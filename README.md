# sandbox-shim

A deliberately narrow HTTP front for the local `syschange` orchestrator, so an
n8n workflow can plan and approve system changes **without n8n having a shell**.

## Why this exists

n8n 2.x disables the Execute Command node by default
(`dist/modules/breaking-changes/rules/v2/disabled-nodes.rule.js` lists
`n8n-nodes-base.executeCommand`). Re-enabling it would hand a browser-reachable
web app arbitrary command execution on the host. This process exposes exactly
two operations instead — `/plan` and `/approve` — and nothing else:

* no "run arbitrary command" endpoint, no eval, no shell parameter
* every operation is a **fixed argv** invoking `syschange-run`; the only
  caller-controlled values are the change request text and the run id
* `run_id` is regex-validated (`run-[A-Za-z0-9-]+`) before syschange ever sees
  it, so `"; rm -rf /"` is a 400, not a shell
* bound to the docker bridge gateway only, never `0.0.0.0`, so it is not
  reachable from the LAN
* requires a shared token on every endpoint except `/health`
* runs as the invoking user, never root (`syschange-run` refuses root anyway)
* every call is appended to an audit log

`syschange`'s own approval gate stays authoritative: `plan` cannot apply
anything, and `approve` requires an explicit run id.

## Files

| path | role |
|---|---|
| `shim.py` | the service (stdlib only, no dependencies) |
| `sandbox-shim.service` | systemd unit — **source of truth**, symlinked into `~/.config/systemd/user/` |
| `bridge-check.sh` | one-shot diagnostic for the n8n → shim path |

## Paths

| thing | location |
|---|---|
| token | `~/.config/sandbox-shim/token` (0600, **not** in this repo) |
| audit log | `~/.local/state/sandbox-shim/audit.log` |
| bind | `172.19.0.1:9922` (the `n8n-workflows_n8n-net` gateway) |
| n8n webhook | `POST http://localhost:5678/webhook/syschange` |

The token is stored as an n8n credential (`Sandbox Shim Token`,
`httpHeaderAuth`), never in the workflow JSON. The n8n-facing workflow export
lives at `n8n/sandbox-syschange-workflow.json`.

## Setup

```bash
# token
mkdir -p ~/.config/sandbox-shim
python3 -c "import secrets; print(secrets.token_urlsafe(32))" > ~/.config/sandbox-shim/token
chmod 600 ~/.config/sandbox-shim/token

# unit (symlink so this repo stays the single source of truth)
ln -sf ~/sandbox-shim/sandbox-shim.service ~/.config/systemd/user/sandbox-shim.service
systemctl --user daemon-reload
systemctl --user enable --now sandbox-shim.service
```

## Verify

```bash
./bridge-check.sh
curl -s http://172.19.0.1:9922/health
```

## Gotchas that cost real time

**`RestrictNamespaces=true` and `CapabilityBoundingSet=` break bubblewrap.**
Both make `bwrap` fail with `Can't open source /: Function not implemented`,
which surfaces as every syschange step returning `rc=126` /
`SandboxUnavailable`. `ProtectSystem=full`, `ProtectHome=read-only` and
`PrivateTmp=true` are all safe and are kept. Verified by bisecting each
directive in a throwaway unit.

**`MemoryDenyWriteExecute=true` breaks V8.** The planner spawns
`opencode run`, and V8 must `mmap` its JIT pages `PROT_EXEC` during heap setup,
so node aborts at startup with a `SIGTRAP` core dump. Attribute a core dump to
its unit with `coredumpctl info <PID>` — it prints a **Control Group** field.

**PATH must include the mise dirs.** systemd's default PATH is only
`/usr/local/bin:/usr/bin:/bin`, which omits `~/.local/share/mise/installs/*`.
syschange resolves its planner with `shutil.which("opencode")` and its memory
backend with `which("engram")`; neither resolves, and steps fail with `rc=126`.

**`SHIM_BIND=auto` cannot work here.** It shells out to
`docker network inspect`, which fails inside the unit (no docker socket access)
and silently degrades to `127.0.0.1`, where n8n can never reach it. The unit
pins the address explicitly; `bridge-check.sh` tells you when it moves.

**The firewall rule is tied to a generated bridge name.** The n8n network's
bridge (`br-ab98f2d1701b`) is reassigned if compose recreates it, and the rule
silently stops matching. Re-add it and run `bridge-check.sh`.

**Do not probe service behaviour from your own shell.** A subprocess inherits
*your* mount namespace, not the service's — that is how `ProtectHome=read-only`
looks broken when it is working. Test inside a unit.

## Security note

The n8n webhook itself requires `X-Sandbox-Key`. Without it, any page in a
browser on this machine could POST to the webhook, and n8n would authenticate
to this shim on the attacker's behalf. Both credentials are separate on purpose:
the caller key protects the webhook, the shim token protects the shim.
