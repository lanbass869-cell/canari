# -*- coding: utf-8 -*-
"""mcp_probe.py - read-only MCP endpoint probe for measurement capsules.

What it does: `initialize`, then `notifications/initialized`, then `tools/list`,
over streamable HTTP. It never calls a tool. That is the same read-only shape
mcpcost and ProtocolProbe use, and it is the comparison
draft-templeman-scitt-measurement-capsule-01 names ("an MCP endpoint's registry
declaration vs its live initialization").

What it refuses to do: collapse different failures into one bucket. The draft
requires UNCHECKABLE to be a first-class outcome and never recorded as a pass, a
failure, a zero or an absence. So every non-success is classified:

    unreachable   transport failed (DNS, refused, timeout)
    auth          the server answered 401/403/402
    not_mcp       an answer with no MCP shape (HTML page, empty body)
    http_error    other non-2xx
    unsupported_version  the server rejected the requested protocol version

A caller that maps "unreachable" to "dead" has reintroduced the exact bug the
draft is trying to prevent.
"""
import hashlib
import json
import time
import urllib.error
import urllib.request

DEFAULT_PROTOCOL = "2025-06-18"
CLIENT_INFO = {"name": "canari-probe", "version": "0.1.0"}
MAX_BODY = 2 * 1024 * 1024


def _post(url, payload, timeout, headers=None):
    """POST one JSON-RPC message. Returns (status, body_text_or_None, err)."""
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "canari-probe/0.1"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(MAX_BODY).decode("utf-8", "replace")
            return r.status, body, None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:
            body = None
        return e.code, body, None
    except Exception as e:
        return None, None, "%s: %s" % (type(e).__name__, str(e)[:120])


def _parse_jsonrpc(body):
    """Return the decoded JSON-RPC message, or None.

    Streamable HTTP servers answer either with a bare JSON body or with an SSE
    stream. The SSE form starts with `event: message` and then a `data:` line:

        event: message
        data: {"result": {...}}

    BUG fixed 2026-11-15: the first version only looked for a body that *began*
    with `data:`, so every SSE reply was classified `not_mcp` -- i.e. a working
    MCP server was recorded as contradicting its own registry declaration. Six
    of 36 real endpoints were branded INCONSISTENT for this reason. That is the
    single worst kind of error a measurement tool can make, so the SSE scan now
    walks every line and takes the first JSON-RPC payload it finds.
    """
    if not body:
        return None
    text = body.strip()
    if not text:
        return None
    # bare JSON first: cheapest and unambiguous
    try:
        return json.loads(text)
    except Exception:
        pass
    # SSE: find the first data: line that carries a JSON-RPC message
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.lower().startswith("data:"):
            continue
        chunk = line[5:].strip()
        if not chunk:
            continue
        try:
            msg = json.loads(chunk)
        except Exception:
            continue
        if isinstance(msg, dict) and ("result" in msg or "error" in msg
                                      or msg.get("jsonrpc")):
            return msg
    return None


def _classify_http(status):
    if status in (401, 403, 402):
        return "auth"
    if status is not None and not (200 <= status < 300):
        return "http_error"
    return None


def probe_endpoint(url, timeout=15, protocol_version=DEFAULT_PROTOCOL, headers=None):
    """Read-only probe. Returns a dict; never raises for a remote failure."""
    out = {
        "url": url,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "requested_protocol_version": protocol_version,
        "reachable": False,
        "http_status": None,
        "protocol_version": None,
        "server_info": None,
        "tool_names": None,
        "tool_count": None,
        "outcome": None,
        "error": None,
        # digest of the raw initialize response bytes: a capsule's sources must
        # be digests, so the probe has to hand one back rather than the body
        "initialize_response_sha256": None,
    }

    status, body, err = _post(url, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": protocol_version,
                   "capabilities": {},
                   "clientInfo": CLIENT_INFO},
    }, timeout, headers)
    out["http_status"] = status
    if body is not None:
        out["initialize_response_sha256"] = hashlib.sha256(
            body.encode("utf-8")).hexdigest()
    if err:
        out["outcome"] = "unreachable"
        out["error"] = err
        return out
    kind = _classify_http(status)
    if kind:
        out["outcome"] = kind
        out["error"] = "HTTP %s" % status
        return out
    msg = _parse_jsonrpc(body)
    if not isinstance(msg, dict):
        out["outcome"] = "not_mcp"
        out["error"] = "response was not JSON-RPC"
        return out
    if msg.get("error"):
        e = msg["error"] if isinstance(msg["error"], dict) else {}
        code = e.get("code")
        out["outcome"] = ("unsupported_version"
                          if code in (-32022, -32602) else "not_mcp")
        out["error"] = "JSON-RPC error %s: %s" % (code, str(e.get("message"))[:100])
        return out
    result = msg.get("result") or {}
    out["reachable"] = True
    out["protocol_version"] = result.get("protocolVersion")
    out["server_info"] = result.get("serverInfo")

    # notifications/initialized carries no id and expects no body; ignore result
    _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, timeout, headers)

    status2, body2, err2 = _post(url, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        timeout, headers)
    if err2:
        out["outcome"] = "partial"
        out["error"] = "tools/list failed: %s" % err2
        return out
    msg2 = _parse_jsonrpc(body2)
    if not isinstance(msg2, dict) or msg2.get("error"):
        out["outcome"] = "partial"
        out["error"] = "tools/list returned no tool list"
        return out
    tools = (msg2.get("result") or {}).get("tools") or []
    if isinstance(tools, list):
        out["tool_names"] = sorted(str(t.get("name")) for t in tools
                                   if isinstance(t, dict) and t.get("name"))
        out["tool_count"] = len(out["tool_names"])
    out["outcome"] = "alive"
    return out
