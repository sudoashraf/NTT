"""
Bulk / multi-target ping — ping a list of hosts and report a summary.

Targets can be supplied as a Python list or read from a file (one per line).
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from ntt.config import DEFAULT_PING_COUNT, DEFAULT_PING_TIMEOUT
from ntt.core.ping import ping
from ntt.core.utils import Status, TestResult


def _load_targets_from_file(path: str) -> List[str]:
    """Read one hostname/IP per line, ignoring blanks and ``#`` comments."""
    targets: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line.split()[0])  # first token only
    return targets


def bulk_ping(
    targets: Optional[List[str]] = None,
    file_path: Optional[str] = None,
    count: int = DEFAULT_PING_COUNT,
    timeout: int = DEFAULT_PING_TIMEOUT,
    workers: int = 10,
) -> TestResult:
    """Ping multiple targets concurrently and return a summary.

    Supply *targets* directly, or set *file_path* to a newline-delimited file.
    """
    if file_path:
        if not os.path.isfile(file_path):
            return TestResult(
                title="Bulk Ping",
                status=Status.ERROR,
                summary=f"File not found: {file_path}",
            )
        targets = _load_targets_from_file(file_path)

    if not targets:
        return TestResult(
            title="Bulk Ping",
            status=Status.ERROR,
            summary="No targets supplied.",
        )

    results: list[tuple[str, TestResult]] = []

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as pool:
        futures = {pool.submit(ping, t, count, timeout): t for t in targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                res = future.result()
            except Exception as exc:
                res = TestResult(
                    title="Ping",
                    status=Status.ERROR,
                    target=target,
                    summary=str(exc),
                )
            results.append((target, res))

    # Sort by original order
    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r[0], 999))

    up = sum(1 for _, r in results if r.status in (Status.SUCCESS, Status.PARTIAL))
    down = len(results) - up

    details: list[str] = []
    for target, res in results:
        badge = "UP" if res.status in (Status.SUCCESS, Status.PARTIAL) else "DOWN"
        summary_short = res.summary[:60] if res.summary else ""
        details.append(f"[{badge:>4}]  {target:<30}  {summary_short}")

    overall = Status.SUCCESS if down == 0 else Status.PARTIAL if up > 0 else Status.FAILURE
    summary = f"{up} reachable, {down} unreachable out of {len(results)} host(s)."

    return TestResult(
        title="Bulk Ping",
        status=overall,
        summary=summary,
        details=details,
    )
