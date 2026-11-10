# -*- coding: utf-8 -*-
"""dead_letter.py - failure audit: counts of failed operations, never silent.

Rationale (plan section 5.4, learning from RUSE): public failure counts
prevent pass-rate inflation. If you claim 95% success but don't show
that you had 200 timeouts, the 95% is meaningless.
"""
import json, os, time


class DeadLetterLog:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.entries = json.load(f)
            except Exception:
                self.entries = []

    def record(self, operation, target, error, registry=""):
        self.entries.append({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "operation": operation,
            "target": target,
            "registry": registry,
            "error": error[:200],
        })

    def save(self):
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.entries, f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    def summary(self):
        by_op = {}
        for e in self.entries:
            by_op[e["operation"]] = by_op.get(e["operation"], 0) + 1
        return {"total": len(self.entries), "by_operation": by_op}

    def clear(self):
        self.entries = []
        self.save()
