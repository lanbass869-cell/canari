# -*- coding: utf-8 -*-
"""mcp_gate.py - canari-mcp-gate: a stdio wrapper that gates an MCP server
before it is started.

Point a client's stdio MCP entry at this program instead of the real command:

    {
      "command": "canari-mcp-gate",
      "args": ["--store", "/abs/path/out", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }

It derives the component the wrapped command will run (npm / PyPI / a remote
URL), asks the signed ledger for a decision, and only then execs the real
command. stdio is proxied byte-for-byte in both directions, so MCP framing is
untouched: nothing is parsed, buffered or rewritten.

Design notes
------------
* Fail-open by default. A component with no attestation is UNKNOWN, and UNKNOWN
  runs the server. A gate that breaks every server it has never seen would be
  uninstalled after one use. Use --on-unknown=block for a strict posture.
* Nothing is written to stdout except the child's own bytes. All diagnostics go
  to stderr, because stdout is the MCP transport.
* This is a *configuration-level* gate: the user can remove the wrapper. It does
  not, and cannot, stop someone editing their own MCP config.

Exit codes: 0 child exited normally (its own code is propagated), 5 blocked by
ledger, 6 review not confirmed, 3 usage / store error, 127 child not found.
"""
import argparse
import os
import subprocess
import sys
import threading

from canari.consumer import check_component

ALLOW, BLOCK, REVIEW = "ALLOW", "BLOCK", "REVIEW"

# Launch verbs that name a package directly, mapped to the ledger's registry.
_RUNNERS = {
    "npx": "npm",
    "bunx": "npm",
    "pnpx": "npm",
    "uvx": "pypi",
    "pipx": "pypi",
}
_BARE_RUNNERS = {"node", "python", "python3", "py", "deno", "bun", "uv"}


def _basename(tok):
    prog = tok.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    return prog[:-4] if prog.endswith(".exe") else prog


def _split_spec(spec):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3'); 'pkg' -> ('pkg', None)."""
    if not spec or spec.startswith("-"):
        return None
    if spec.startswith("@"):
        at = spec.find("@", 1)
        return (spec, None) if at == -1 else (spec[:at], spec[at + 1:])
    if "==" in spec:
        name, _, ver = spec.partition("==")
        return name, (ver or None)
    if "@" in spec:
        name, _, ver = spec.partition("@")
        return name, (ver or None)
    return spec, None


def component_of(argv):
    """Best-effort (registry, name, version) for a launch command.

    Returns None when the command does not name a component we can look up --
    a local script, an absolute path, a multi-subcommand tool. Callers treat
    that as UNKNOWN rather than guessing.
    """
    if not argv:
        return None
    prog = _basename(argv[0])

    if prog in _RUNNERS:
        rest = [t for t in argv[1:] if not t.startswith("-")]
        if not rest:
            return None
        spec = _split_spec(rest[0])
        if not spec:
            return None
        return (_RUNNERS[prog], spec[0], spec[1])

    if prog.startswith("mcp-server-"):
        # A console entry point installed by a PyPI package of the same name.
        spec = _split_spec(argv[0])
        if spec:
            return ("pypi", spec[0], spec[1])

    if prog in _BARE_RUNNERS:
        # python -m pkg / node path/to.js: not a package identity we can resolve.
        return None

    return None


def _proxy(child_argv):
    """Run the child and shuttle stdio verbatim. Returns the child's exit code."""
    try:
        child = subprocess.Popen(
            child_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,          # inherit: server logs stay visible
            bufsize=0,
        )
    except FileNotFoundError:
        sys.stderr.write("canari-mcp-gate: command not found: %s\n" % child_argv[0])
        return 127

    def pump_stdin():
        try:
            while True:
                chunk = sys.stdin.buffer.read(65536)
                if not chunk:
                    break
                child.stdin.write(chunk)
                child.stdin.flush()
        except Exception:
            pass
        finally:
            try:
                child.stdin.close()
            except Exception:
                pass

    def pump_stdout():
        try:
            while True:
                chunk = child.stdout.read(65536)
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
        except Exception:
            pass

    t_in = threading.Thread(target=pump_stdin, daemon=True)
    t_out = threading.Thread(target=pump_stdout, daemon=True)
    t_in.start()
    t_out.start()
    code = child.wait()
    t_out.join(timeout=5)
    return code


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="canari-mcp-gate",
        description="Gate an MCP server against the signed ledger, then run it.")
    ap.add_argument("--store", default=os.environ.get("CANARI_STORE", "out"),
                    help="attestation store dir (default: $CANARI_STORE or ./out)")
    ap.add_argument("--registry", default=None,
                    help="override the derived registry (npm|pypi|mcp-registry|dsh-registry)")
    ap.add_argument("--name", default=None, help="override the derived component name")
    ap.add_argument("--version", default=None, help="pin an exact version")
    ap.add_argument("--policy", default="default", help="gate policy")
    ap.add_argument("--key", default=None, help="public key JSON (enables signature verification)")
    ap.add_argument("--on-unknown", choices=["allow", "block", "review"], default="allow",
                    help="what to do when the ledger has no attestation (default: allow)")
    ap.add_argument("--allow-review", action="store_true",
                    help="run even when the gate says REVIEW")
    ap.add_argument("--quiet", action="store_true", help="suppress the decision banner")
    ap.add_argument("child", nargs=argparse.REMAINDER,
                    help="-- command to wrap, e.g. -- npx -y some-server")
    a = ap.parse_args(argv)

    child = list(a.child)
    if child and child[0] == "--":
        child = child[1:]
    if not child:
        ap.error("no command given; use: canari-mcp-gate --store DIR -- <command> [args...]")

    ident = component_of(child)
    registry = a.registry or (ident[0] if ident else None)
    name = a.name or (ident[1] if ident else None)
    version = a.version or (ident[2] if ident else None)

    decision = ALLOW
    reasons = []

    if registry and name and os.path.isdir(a.store):
        res = check_component(a.store, registry, name, version=version,
                              key_path=a.key, policy=a.policy)
        if not res["found"]:
            if a.on_unknown == "block":
                decision, reasons = BLOCK, res["reasons"]
            elif a.on_unknown == "review" and not a.allow_review:
                decision, reasons = REVIEW, res["reasons"]
        else:
            decision = res["decision"]
            reasons = res["reasons"]
    elif not os.path.isdir(a.store):
        sys.stderr.write("canari-mcp-gate: store not found: %s (running anyway)\n" % a.store)

    subject = "%s:%s%s" % (registry, name, ("@" + version) if version else "") if (registry and name) else "<unidentified>"
    if not a.quiet:
        sys.stderr.write("canari-mcp-gate: %s -> %s\n" % (subject, decision))
        for r in reasons[:5]:
            sys.stderr.write("  - %s\n" % r)

    if decision == BLOCK:
        sys.stderr.write("canari-mcp-gate: blocked; not starting %s\n" % child[0])
        return 5
    if decision == REVIEW and not a.allow_review:
        sys.stderr.write("canari-mcp-gate: review required; re-run with --allow-review to accept\n")
        return 6

    return _proxy(child)


if __name__ == "__main__":
    sys.exit(main())
