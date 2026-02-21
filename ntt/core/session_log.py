"""
Session logger — automatically records every TestResult to a log file.

The logger is a lightweight singleton.  Call ``SessionLogger.get()`` to
obtain the instance, then ``.log(result)`` after each test.

Log files are written to ``./ntt_logs/`` with a timestamped name per session.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import List, Optional

from ntt.core.utils import TestResult


class SessionLogger:
    """Append-only JSON-lines logger for a single interactive session."""

    _instance: Optional["SessionLogger"] = None

    def __init__(self, log_dir: str = "") -> None:
        self._log_dir = log_dir or os.path.join(os.getcwd(), "ntt_logs")
        os.makedirs(self._log_dir, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_path = os.path.join(self._log_dir, f"session_{ts}.jsonl")
        self._results: list[TestResult] = []
        self._enabled = True

    # ── Singleton access ──────────────────────────────────────────────────

    @classmethod
    def get(cls, log_dir: str = "") -> "SessionLogger":
        """Return the global session logger (create on first call)."""
        if cls._instance is None:
            cls._instance = cls(log_dir)
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Discard the singleton (for tests)."""
        cls._instance = None

    # ── Properties ────────────────────────────────────────────────────────

    @property
    def log_path(self) -> str:
        return self._log_path

    @property
    def results(self) -> List[TestResult]:
        """All results logged in this session (in-memory copy)."""
        return list(self._results)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    # ── Core API ──────────────────────────────────────────────────────────

    def log(self, result: TestResult) -> None:
        """Append a result to the in-memory list and flush to disk."""
        self._results.append(result)
        if not self._enabled:
            return
        entry = {
            "title": result.title,
            "status": result.status.value,
            "target": result.target,
            "summary": result.summary,
            "details": result.details,
            "raw_output": result.raw_output,
            "timestamp": result.timestamp,
        }
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass  # Best-effort — don't crash the tool for a log failure

    def summary(self) -> str:
        """Return a one-line summary of the current session."""
        total = len(self._results)
        if total == 0:
            return "No tests run in this session."
        from ntt.core.utils import Status
        passed = sum(1 for r in self._results if r.status == Status.SUCCESS)
        failed = sum(1 for r in self._results if r.status in (Status.FAILURE, Status.ERROR))
        partial = total - passed - failed
        return (
            f"Session: {total} test(s) — "
            f"{passed} passed, {failed} failed, {partial} partial/other.  "
            f"Log: {self._log_path}"
        )
