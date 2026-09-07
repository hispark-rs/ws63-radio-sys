#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Compare pinned hostap security decisions with the official advisory index."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import tomllib
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "upstream" / "hostap-2.11.json"
PROFILE_ROOT = ROOT / "port" / "hostap"
INDEX_URL = "https://w1.fi/security/"
ADVISORY = re.compile(r'href=["\'](?:https://w1\.fi/security/)?(20[0-9]{2}-[0-9]+)/')
ADVISORY_ID = re.compile(r"20[0-9]{2}-[0-9]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
RESOLVED_STATUSES = {"fixed", "not-affected"}
KNOWN_STATUSES = RESOLVED_STATUSES | {"under-investigation", "accepted-risk"}


class ContractError(ValueError):
    """The versioned security decision does not match its source profile."""


def advisory_key(value: str) -> tuple[int, int]:
    year, sequence = value.split("-", 1)
    return int(year), int(sequence)


def discover(index: str) -> set[str]:
    return set(ADVISORY.findall(index))


def fetch_index() -> str:
    request = urllib.request.Request(
        INDEX_URL,
        headers={"User-Agent": "ws63-radio-sys-hostap-security-radar/2"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def _strings(value: object, field: str) -> list[str]:
    if isinstance(value, str) and value:
        return [value]
    if (
        isinstance(value, list)
        and value
        and all(isinstance(item, str) and item for item in value)
    ):
        return value
    raise ContractError(f"{field} must be a non-empty string or string list")


def _define_names(defines: set[str]) -> set[str]:
    return {value.split("=", 1)[0] for value in defines}


def load_profile(
    name: str,
    profile_root: pathlib.Path = PROFILE_ROOT,
    stack: tuple[str, ...] = (),
) -> tuple[set[str], set[str]]:
    if name in stack:
        raise ContractError(f"hostap profile inheritance cycle: {' -> '.join((*stack, name))}")
    if pathlib.Path(name).name != name:
        raise ContractError(f"hostap security profile must be a file name: {name}")
    path = profile_root / name
    if path.parent != profile_root or not path.is_file():
        raise ContractError(f"hostap security profile does not exist: {name}")
    profile = tomllib.loads(path.read_text())
    sources: set[str] = set()
    defines: set[str] = set()
    parent = profile.get("extends")
    if parent is not None:
        if not isinstance(parent, str):
            raise ContractError(f"hostap profile {name} has invalid extends")
        sources, defines = load_profile(parent, profile_root, (*stack, name))
    for field in ("upstream_sources", "port_sources"):
        values = profile.get(field, [])
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            raise ContractError(f"hostap profile {name} has invalid {field}")
        sources.update(values)
    values = profile.get("defines", [])
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ContractError(f"hostap profile {name} has invalid defines")
    defines.update(values)
    return sources, defines


def validate_metadata(
    metadata: dict[str, object], profile_root: pathlib.Path = PROFILE_ROOT
) -> dict[str, str]:
    backports = metadata.get("security_backports")
    dispositions = metadata.get("security_dispositions")
    if not isinstance(backports, list) or not isinstance(dispositions, list):
        raise ContractError("security_backports and security_dispositions must be lists")

    decisions: dict[str, str] = {}
    for entry in backports:
        if not isinstance(entry, dict):
            raise ContractError("security backport entry must be an object")
        advisory = entry.get("advisory")
        if not isinstance(advisory, str) or not ADVISORY_ID.fullmatch(advisory):
            raise ContractError(f"invalid hostap advisory id: {advisory!r}")
        if advisory in decisions:
            raise ContractError(f"duplicate hostap security decision: {advisory}")
        decisions[advisory] = "fixed"

    for entry in dispositions:
        if not isinstance(entry, dict):
            raise ContractError("security disposition entry must be an object")
        advisory = entry.get("advisory")
        if not isinstance(advisory, str) or not ADVISORY_ID.fullmatch(advisory):
            raise ContractError(f"invalid hostap advisory id: {advisory!r}")
        if advisory in decisions:
            raise ContractError(f"duplicate hostap security decision: {advisory}")
        if entry.get("url") != f"https://w1.fi/security/{advisory}/":
            raise ContractError(f"hostap advisory URL drift: {advisory}")
        status = entry.get("status")
        if status not in KNOWN_STATUSES:
            raise ContractError(
                f"unknown hostap advisory status for {advisory}: {status!r}"
            )
        decisions[advisory] = str(status)

        fix = entry.get("official_fix_commit")
        if not isinstance(fix, str) or not COMMIT.fullmatch(fix):
            raise ContractError(f"invalid official fix commit for {advisory}")
        reviewed_on = entry.get("reviewed_on")
        try:
            dt.date.fromisoformat(str(reviewed_on))
        except ValueError as error:
            raise ContractError(
                f"invalid review date for {advisory}: {reviewed_on!r}"
            ) from error
        if not isinstance(entry.get("review_owner"), str) or not entry["review_owner"]:
            raise ContractError(f"missing review owner for {advisory}")
        _strings(entry.get("recheck_when"), f"{advisory}.recheck_when")

        if status != "not-affected":
            continue
        affected_source = entry.get("affected_source")
        if not isinstance(affected_source, str) or not affected_source:
            raise ContractError(f"not-affected advisory lacks affected source: {advisory}")
        checks = entry.get("profile_checks")
        if not isinstance(checks, list) or not checks:
            raise ContractError(f"not-affected advisory lacks profile checks: {advisory}")
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("profile"), str):
                raise ContractError(f"invalid profile check for {advisory}")
            profile = str(check["profile"])
            sources, defines = load_profile(profile, profile_root)
            define_names = _define_names(defines)
            predicates = 0
            checked_absent_sources: set[str] = set()
            for source in (
                _strings(
                    check["source_absent"], f"{advisory}.{profile}.source_absent"
                )
                if "source_absent" in check
                else []
            ):
                predicates += 1
                checked_absent_sources.add(source)
                if source in sources:
                    raise ContractError(
                        f"{advisory} no longer not-affected: {profile} includes {source}"
                    )
            if affected_source not in checked_absent_sources:
                raise ContractError(
                    f"{advisory}/{profile} does not check affected source {affected_source}"
                )
            for define in (
                _strings(
                    check["define_absent"], f"{advisory}.{profile}.define_absent"
                )
                if "define_absent" in check
                else []
            ):
                predicates += 1
                if define in define_names:
                    raise ContractError(
                        f"{advisory} no longer not-affected: {profile} defines {define}"
                    )
            for define in (
                _strings(
                    check["define_present"], f"{advisory}.{profile}.define_present"
                )
                if "define_present" in check
                else []
            ):
                predicates += 1
                if define not in define_names:
                    raise ContractError(
                        f"{advisory} no longer not-affected: {profile} lacks {define}"
                    )
            if predicates == 0:
                raise ContractError(
                    f"profile check has no machine predicate: {advisory}/{profile}"
                )
    return decisions


def evaluate(
    index: str,
    metadata: dict[str, object],
    profile_root: pathlib.Path = PROFILE_ROOT,
) -> tuple[list[str], list[str], list[str], dict[str, str]]:
    radar = metadata["security_radar"]
    if not isinstance(radar, dict):
        raise ContractError("security_radar must be an object")
    floor = advisory_key(str(radar["advisory_floor_exclusive"]))
    official = sorted(
        (value for value in discover(index) if advisory_key(value) > floor),
        key=advisory_key,
    )
    decisions = validate_metadata(metadata, profile_root)
    missing = [value for value in official if value not in decisions]
    unresolved = [
        value for value in official if decisions.get(value) not in RESOLVED_STATUSES
    ]
    return official, missing, unresolved, decisions


def report(
    metadata: dict[str, object],
    official: list[str],
    missing: list[str],
    unresolved: list[str],
    decisions: dict[str, str],
) -> str:
    status = "FAIL" if missing or unresolved else "PASS"
    lines = [
        "# hostap security radar",
        "",
        f"- Status: **{status}**",
        f"- Source: {INDEX_URL}",
        f"- Pinned hostap commit: `{metadata['commit']}`",
        f"- Official advisories after release floor: {', '.join(official) or 'none'}",
        f"- Missing decisions: {', '.join(missing) or 'none'}",
        f"- Unresolved decisions: {', '.join(unresolved) or 'none'}",
        "",
        "## Decisions",
        "",
    ]
    lines.extend(
        f"- `{advisory}`: `{decisions.get(advisory, 'missing')}`"
        for advisory in official
    )
    lines.append("")
    if missing or unresolved:
        lines.extend(
            [
                "## Required action",
                "",
                "Review each unresolved official advisory. Backport applicable fixes or",
                "record a machine-checked applicability disposition in the versioned",
                "manifest. A pending or accepted-risk decision remains release-blocking.",
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
    metadata: dict[str, object] = {
        "security_radar": {"advisory_floor_exclusive": "2024-2"},
        "security_backports": [
            {"advisory": "2026-1"},
            {"advisory": "2026-2"},
            {"advisory": "2026-3"},
        ],
        "security_dispositions": [],
    }
    official, missing, unresolved, _ = evaluate(fixture, metadata)
    assert official == ["2026-1", "2026-2", "2026-3"]
    assert missing == []
    assert unresolved == []
    backports = metadata["security_backports"]
    assert isinstance(backports, list)
    backports.pop()
    _, missing, _, _ = evaluate(fixture, metadata)
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
        official, missing, unresolved, decisions = evaluate(index, metadata)
        output = report(metadata, official, missing, unresolved, decisions)
        status = 1 if missing or unresolved else 0
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
        arguments.report.parent.mkdir(parents=True, exist_ok=True)
        arguments.report.write_text(output)
    print(output)
    return status


if __name__ == "__main__":
    sys.exit(main())
