#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Compare the pinned hostap security set with the official advisory index."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "upstream" / "hostap-2.11.json"
INDEX_URL = "https://w1.fi/security/"
ADVISORY = re.compile(r'href=["\'](?:https://w1\.fi/security/)?(20[0-9]{2}-[0-9]+)/')


def advisory_key(value: str) -> tuple[int, int]:
    year, sequence = value.split("-", 1)
    return int(year), int(sequence)


def discover(index: str) -> set[str]:
    return set(ADVISORY.findall(index))


def fetch_index() -> str:
    request = urllib.request.Request(
        INDEX_URL,
        headers={"User-Agent": "ws63-radio-sys-hostap-security-radar/1"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def evaluate(index: str, metadata: dict[str, object]) -> tuple[list[str], list[str]]:
    radar = metadata["security_radar"]
    assert isinstance(radar, dict)
    floor = advisory_key(str(radar["advisory_floor_exclusive"]))
    official = sorted(
        (value for value in discover(index) if advisory_key(value) > floor),
        key=advisory_key,
    )
    backports = metadata["security_backports"]
    assert isinstance(backports, list)
    covered = {str(entry["advisory"]) for entry in backports}
    missing = [value for value in official if value not in covered]
    return official, missing


def report(metadata: dict[str, object], official: list[str], missing: list[str]) -> str:
    status = "FAIL" if missing else "PASS"
    lines = [
        "# hostap security radar",
        "",
        f"- Status: **{status}**",
        f"- Source: {INDEX_URL}",
        f"- Pinned hostap commit: `{metadata['commit']}`",
        f"- Official advisories after release floor: {', '.join(official) or 'none'}",
        f"- Missing from source manifest: {', '.join(missing) or 'none'}",
        "",
    ]
    if missing:
        lines.extend(
            [
                "## Required action",
                "",
                "Review each missing official advisory, backport applicable fixes onto the",
                "hash-pinned maintenance branch, rebuild both target archives, and update",
                "the source manifest plus host/vector tests. Do not silently mark an",
                "advisory as covered without an applied commit or an explicit applicability",
                "decision in the versioned manifest.",
                "",
            ]
        )
    return "\n".join(lines)


def self_test() -> None:
    fixture = """
      <a href="2024-2/">old</a>
      <a href="2026-1/">one</a>
      <a href="https://w1.fi/security/2026-2/">two</a>
      <a href="2026-3/">three</a>
    """
    metadata = {
        "security_radar": {"advisory_floor_exclusive": "2024-2"},
        "security_backports": [
            {"advisory": "2026-1"},
            {"advisory": "2026-2"},
            {"advisory": "2026-3"},
        ],
    }
    official, missing = evaluate(fixture, metadata)
    assert official == ["2026-1", "2026-2", "2026-3"]
    assert missing == []
    metadata["security_backports"].pop()
    _, missing = evaluate(fixture, metadata)
    assert missing == ["2026-3"]
    print("hostap security radar parser self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index-file", type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return 0

    metadata = json.loads(MANIFEST.read_text())
    try:
        index = (
            arguments.index_file.read_text()
            if arguments.index_file is not None
            else fetch_index()
        )
        official, missing = evaluate(index, metadata)
        output = report(metadata, official, missing)
        status = 1 if missing else 0
    except Exception as error:
        output = "\n".join(
            [
                "# hostap security radar",
                "",
                "- Status: **ERROR**",
                f"- Source: {INDEX_URL}",
                f"- Pinned hostap commit: `{metadata['commit']}`",
                f"- Diagnostic: `{type(error).__name__}: {error}`",
                "",
                "The advisory state is unknown. Check network/source availability and rerun",
                "the radar; do not interpret this result as a clean security state.",
                "",
            ]
        )
        status = 2
    if arguments.report is not None:
        arguments.report.write_text(output)
    print(output)
    return status


if __name__ == "__main__":
    sys.exit(main())
