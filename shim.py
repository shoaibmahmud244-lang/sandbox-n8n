#!/usr/bin/env python3
"""syschange shim — a deliberately narrow HTTP front for the syschange orchestrator.

This exists so an n8n workflow can drive syschange WITHOUT n8n having a shell.
n8n 2.x disables the Execute Command node by default
(dist/modules/breaking-changes/rules/v2/disabled-nodes.rule.js lists
n8n-nodes-base.executeCommand), and re-enabling it would hand a browser-reachable,
currently unauthenticated web app arbitrary command execution on this machine.

So this process exposes exactly two operations and nothing else. There is no
"run arbitrary command" endpoint, no eval, no shell parameter. Each operation is
a fixed argv invoking syschange-run; the only caller-controlled value is the
change request text and the run id.

Security properties:
  * Binds to the docker bridge gateway only (172.19.0.1), never 0.0.0.0, so it
    is not reachable from the LAN and not from outside the host.
  * Requires a shared token on every endpoint except /health.
  * syschange's own approval gate is still authoritative: plan() cannot apply
    anything, and approve() requires an explicit run id.
  * Runs as the invoking user, never root. syschange-run refuses to run as root
    anyway.
  * Every invocation is logged to an audit file.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.environ.get("HOME", "/home/solonext")
SYSCHANGE = os.path.join(HOME, "ai-system", "syschange", "syschange-run")
TOKEN_FILE = os.path.join(HOME, ".config", "sandbox-shim", "token")
AUDIT = os.path.join(HOME, ".local", "state", "sandbox-shim", "audit.log")
# "auto" resolves the docker bridge gateway for the n8n network, so the shim keeps
# working if `docker compose down` reassigns the subnet. Binding to the gateway
# rather than 0.0.0.0 is what keeps this off the LAN.
BIND_HOST = os.environ.get("SHIM_BIND", "auto")
BIND_PORT = int(os.environ.get("SHIM_PORT", "9922"))
N8N_NETWORK = os.environ.get("SHIM_NETWORK", "n8n-workflows_n8n-net")
# Plan output is human-readable and can be long; bound it so one call cannot
# exhaust memory or run unbounded.
MAX_REQUEST_CHARS = 2000
HARD_TIMEOUT = 600

_lock = threading.Lock()  # syschange takes a run lock; serialise callers


def token() -> str:
    try:
        with open(TOKEN_FILE) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def audit(event: str, detail: str = "") -> None:
    try:
        os.makedirs(os.path.dirname(AUDIT), exist_ok=True)
        with open(AUDIT, "a") as fh:
            fh.write(f"{time.strftime('%F %T')} {event} {detail}\n")
    except OSError:
        pass


def run(argv: list[str]) -> dict:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=HARD_TIMEOUT,
            cwd=os.path.join(HOME, "ai-system", "syschange"),
        )
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout[-20000:],
            "stderr": proc.stderr[-4000:],
        }
    except subprocess.TimeoutExpired:
        return {"exit_code": 124, "stdout": "", "stderr": "shim: timed out"}
    except OSError as exc:
        return {"exit_code": 127, "stdout": "", "stderr": f"shim: {exc}"}


def parse_plan(raw: str) -> dict:
    """Turn syschange's human-readable output into structured data.

    There are two layouts in the wild.

    * approval-pending: the report lists `  s10  [high]  sudo ...` lines and
      prints `APPROVAL REQUIRED`.
    * executed/failed: the report lists `- [ok] s1: df -h -> rc=0 ...` (or
      `- [FAILED] s1: ...`) lines. Parsing only the first layout used to make
      every executed run fall through to `applied=True, step_count=0`, which
      reads as success even when step sN had FAILED.
    """
    run_id = (re.search(r"run id:\s*(\S+)", raw) or [None, None])[1]
    risk = (re.search(r"risk\s*:\s*(\S+)", raw) or [None, None])[1]
    steps = []
    # Pending-format steps:  "  s10  [high]  sudo du ..."
    for m in re.finditer(r"^\s*(s\d+)\s+\[(\w+)\]\s+(.+)$", raw, re.M):
        steps.append({"id": m.group(1), "risk": m.group(2), "command": m.group(3).strip()})
    # Executed-format steps: "- [ok] s1: df -h -> rc=0" / "- [FAILED] sN: ..."
    for m in re.finditer(r"^- \[(OK|FAILED)\] \s*(s\d+):\s*(.+)$", raw, re.M | re.I):
        steps.append({"id": m.group(2), "risk": ("" if m.group(1).lower() == "ok" else "failed"),
                      "command": m.group(3).strip(), "status": m.group(1).lower()})
    approval = bool(re.search(r"APPROVAL REQUIRED", raw))
    # Pre-test evidence printed by syschange before the approval prompt:
    #   "        pre-test: PASS — exit=0, verify=ok, files=1"
    # The printed line carries no step id, so it is surfaced as one report
    # rather than attached per step.
    failed_step = re.search(r"FAILED: step (s\d+) failed", raw)
    return {
        "run_id": run_id,
        "risk": risk,
        "approval_required": approval,
        "applied": (not approval) and not bool(failed_step),
        "step_count": len(steps),
        "steps": steps,
        "pretest_report": "\n".join(
            m.group(0).strip() for m in re.finditer(r"^\s*pre-test:.*$", raw, re.M)
        ),
        "note": (
            "NOTHING WAS CHANGED. Review the steps, then POST /approve with this run_id."
            if approval else ("One or more steps FAILED." if failed_step else "No approval gate was hit.")
        ),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "sandbox-shim/1.0"

    def log_message(self, fmt, *a):  # quieter, we do our own auditing
        pass

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        expected = token()
        given = self.headers.get("X-Sandbox-Token", "")
        # compare_digest so the comparison is not a timing oracle
        return bool(expected) and hmac.compare_digest(expected, given)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True, "syschange": os.path.exists(SYSCHANGE)})
            return
        self._send(403, {"error": "forbidden"})

    def do_POST(self):
        if not self._authorised():
            audit("DENIED", self.path)
            self._send(403, {"error": "bad or missing X-Sandbox-Token"})
            return

        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if n > 64 * 1024:
            self._send(413, {"error": "body too large"})
            return
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, OSError):
            self._send(400, {"error": "invalid JSON"})
            return

        # syschange takes a run lock; one caller at a time avoids lock errors
        # and interleaved output.
        with _lock:
            if self.path == "/plan":
                request = str(body.get("request", "")).strip()[:MAX_REQUEST_CHARS]
                if not request:
                    self._send(400, {"error": "request is required"})
                    return
                audit("PLAN", request[:120])
                r = run([SYSCHANGE, "plan", request])
                out = parse_plan(r["stdout"])
                out["exit_code"] = r["exit_code"]
                if r["exit_code"] != 0:
                    out["error"] = r["stderr"][-500:]
                self._send(200, out)
                return

            if self.path == "/approve":
                run_id = str(body.get("run_id", "")).strip()
                if not re.fullmatch(r"run-[A-Za-z0-9-]+", run_id):
                    self._send(400, {"error": "run_id must look like run-xxxx"})
                    return
                audit("APPROVE", run_id)
                r = run([SYSCHANGE, "approve", run_id, "--yes"])
                self._send(200, {
                    "run_id": run_id,
                    "applied": r["exit_code"] == 0,
                    "exit_code": r["exit_code"],
                    "stdout": r["stdout"][-8000:],
                    "stderr": r["stderr"][-1000:],
                })
                return

        audit("DENIED-PATH", self.path)
        self._send(404, {"error": "unknown endpoint"})


def resolve_bind_host() -> str:
    """Find the docker bridge gateway the n8n container can actually reach.

    Hardcoding the address breaks whenever compose recreates the subnet, which is
    exactly when you least want the workflow to stop working.
    """
    if BIND_HOST != "auto":
        return BIND_HOST
    try:
        out = subprocess.run(
            ["docker", "network", "inspect", N8N_NETWORK, "--format",
             "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
            capture_output=True, text=True, timeout=15,
        )
        gw = out.stdout.strip()
        if gw:
            return gw
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"shim: could not inspect {N8N_NETWORK}: {exc}", file=sys.stderr)
    print("shim: falling back to 127.0.0.1 — the n8n container will NOT reach it",
          file=sys.stderr)
    return "127.0.0.1"


def main() -> int:
    if not os.path.exists(SYSCHANGE):
        print(f"syschange-run not found at {SYSCHANGE}", file=sys.stderr)
        return 1
    if not token():
        print(f"no token at {TOKEN_FILE}", file=sys.stderr)
        return 1
    host = resolve_bind_host()
    srv = ThreadingHTTPServer((host, BIND_PORT), Handler)
    print(f"sandbox-shim listening on {host}:{BIND_PORT}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())