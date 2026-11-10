# -*- coding: utf-8 -*-
"""guard.py - canari-guard: wrap an install command, gate it, then execute.

This is the consumer gate at the only place it matters: the moment a host is
about to install something. It never patches the host - it wraps the command:

    canari-guard -- dsh plugin --profile wbpj add dsh-purge
    canari-guard -- npm install some-mcp-server
    canari-guard -- pip install mcp-server-fetch

Behaviour: parse the component names out of the command, look each up in the
signed ledger, and refuse to execute when the gate says BLOCK. REVIEW requires
--allow-review (the human sees the reasons). Anything unrecognised is passed
through untouched (the guard is not a shell parser).

Exit codes: 0 allowed+executed, 5 blocked by ledger, 6 review not confirmed,
3 usage / store missing, otherwise the wrapped command's own exit code.
"""
import shlex
import subprocess
import sys

from canari.consumer import check_component

INSTALL_VERBS = {"install", "i", "add", "isntall"}
_FLAGS_WITH_VALUE = {"--profile", "-p", "--registry", "--store", "--tag", "--prefix"}


def _split_spec(spec):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3'); 'pkg' -> ('pkg', None)."""
    if not spec or spec.startswith("-"):
        return None
    if spec.startswith("@"):
        at = spec.find("@", 1)
        if at == -1:
            return spec, None
        return spec[:at], spec[at + 1:]
    if "==" in spec:  # PEP 440 pin
        name, _, ver = spec.partition("==")
        return name, (ver or None)
    if "@" in spec:
        name, _, ver = spec.partition("@")
        return name, (ver or None)
    return spec, None


def parse_install(argv):
    """Return (registry, name, version) candidates parsed from an install command.

    Recognised: dsh plugin ... add <pkg>, npm/pnpm/yarn install <pkg>,
    pip/pip3 install <pkg>. Unknown shapes return [] (pass-through).
    """
    if not argv:
        return []
    toks = list(argv)
    prog = toks[0].lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    if prog.endswith(".exe"):
        prog = prog[:-4]
    out = []

    def _collect(registry, start):
        for t in toks[start:]:
            if t.startswith("-"):
                continue
            spec = _split_spec(t)
            if spec:
                out.append((registry, spec[0], spec[1]))

    if prog in ("dsh", "dsh.cmd", "dsh.exe"):
        # dsh plugin [--profile X] add <pkg>...
        if len(toks) > 1 and toks[1].lower() == "plugin":
            idx = None
            for i, t in enumerate(toks[2:], start=2):
                if t.lower() in INSTALL_VERBS:
                    idx = i + 1
                    break
            if idx is not None:
                _collect("dsh-registry", idx)
        return out

    if prog in ("npm", "pnpm", "yarn", "bun"):
        for i, t in enumerate(toks[1:], start=1):
            if t.lower() in INSTALL_VERBS:
                _collect("npm", i + 1)
                break
        return out

    if prog in ("pip", "pip3", "py"):
        # pip install <pkg>; skip "py -m pip install ..."
        for i, t in enumerate(toks[1:], start=1):
            if t.lower() in INSTALL_VERBS:
                _collect("pypi", i + 1)
                break
        return out

    return out


def _lookup(store, registry, name, version, key):
    """dsh plugin names live in the dsh registry but install through npm;
    try the declared registry first, then the npm namespace."""
    res = check_component(store, registry, name, version=version, key_path=key)
    if not res["found"] and registry == "dsh-registry":
        res = check_component(store, "npm", name, version=version, key_path=key)
    return res


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="canari-guard",
                                 description="Gate an install command against the signed ledger, then run it.")
    ap.add_argument("--store", default="out")
    ap.add_argument("--key", default=None)
    ap.add_argument("--policy", default="default")
    ap.add_argument("--policy-file", default=None)
    ap.add_argument("--allow-review", action="store_true",
                    help="proceed when the gate returns REVIEW")
    ap.add_argument("--dry-run", action="store_true",
                    help="evaluate the gate but do not execute the command")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="-- <command> ...")
    a = ap.parse_args(argv)

    cmd = a.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("no command given (usage: canari-guard -- <command> ...)")

    pkgs = parse_install(cmd)
    blocked, review = [], []
    for registry, name, version in pkgs:
        res = _lookup(a.store, registry, name, version, a.key)
        line = "%s:%s%s -> %s" % (registry, name, ("@" + version) if version else "",
                                  res["decision"])
        if res["decision"] == "BLOCK":
            blocked.append((line, res["reasons"]))
        elif res["decision"] == "REVIEW":
            review.append((line, res["reasons"]))
        else:
            print("[guard] %s" % line)

    if not pkgs:
        print("[guard] no install pattern recognised; passing through")

    for line, reasons in blocked:
        print("[guard] BLOCK %s" % line)
        for r in reasons:
            print("        - %s" % r)
    for line, reasons in review:
        print("[guard] REVIEW %s" % line)
        for r in reasons:
            print("        - %s" % r)

    if blocked:
        print("[guard] refusing to run: %d blocked component(s)" % len(blocked))
        return 5
    if review and not a.allow_review:
        print("[guard] refusing to run: %d component(s) need review "
              "(re-run with --allow-review to proceed)" % len(review))
        return 6
    if a.dry_run:
        print("[guard] dry-run: would execute: %s" % " ".join(cmd))
        return 0

    print("[guard] executing: %s" % " ".join(cmd))
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        import shutil
        prog = cmd[0]
        for cand in (prog, prog + ".cmd", prog + ".bat", prog + ".exe"):
            hit = shutil.which(cand)
            if hit:
                try:
                    return subprocess.call([hit] + cmd[1:])
                except OSError:
                    break
        print("[guard] command not found: %s" % prog)
        return 3


if __name__ == "__main__":
    sys.exit(main())
