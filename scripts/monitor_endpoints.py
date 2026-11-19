# -*- coding: utf-8 -*-
"""Compatibility shim: the implementation now lives in canari/monitor_cli.py
so that it ships in the wheel and can be installed as `canari-monitor`.

Kept so that existing invocations (python scripts/monitor_endpoints.py) and the
tests that import this path keep working.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from canari.monitor_cli import (  # noqa: E402,F401
    DEFAULT_MIN_GAP_SECONDS,
    DEFAULT_MIN_OBSERVATIONS,
    EndpointHistory,
    fetch_registry,
    main,
    probe_all,
    probe_endpoint,
    report,
    targets,
)

if __name__ == "__main__":
    sys.exit(0 if main() is not None else 1)
