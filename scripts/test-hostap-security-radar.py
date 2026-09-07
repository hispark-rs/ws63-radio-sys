#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Negative tests for the hostap security release gate."""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-hostap-security-radar.py"
SPEC = importlib.util.spec_from_file_location("hostap_security_radar", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RADAR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RADAR)


def expect_failure(action, message: str) -> None:
    try:
        action()
    except RADAR.ContractError:
        return
    raise AssertionError(message)


def main() -> None:
    metadata = json.loads((ROOT / "upstream/hostap-2.11.json").read_text())
    index = "".join(
        f'<a href="{advisory}/">{advisory}</a>'
        for advisory in ("2026-1", "2026-2", "2026-3", "2026-4", "2026-5")
    )
    official, missing, unresolved, decisions = RADAR.evaluate(index, metadata)
    assert official == ["2026-1", "2026-2", "2026-3", "2026-4", "2026-5"]
    assert missing == [] and unresolved == []
    assert decisions["2026-4"] == "not-affected"
    assert decisions["2026-5"] == "not-affected"

    missing_metadata = copy.deepcopy(metadata)
    missing_metadata["security_dispositions"].pop()
    _, missing, _, _ = RADAR.evaluate(index, missing_metadata)
    assert missing == ["2026-5"]

    duplicate = copy.deepcopy(metadata)
    duplicate["security_dispositions"][0]["advisory"] = "2026-1"
    expect_failure(
        lambda: RADAR.validate_metadata(duplicate),
        "duplicate advisory decisions must fail",
    )

    unresolved_metadata = copy.deepcopy(metadata)
    unresolved_metadata["security_dispositions"][0]["status"] = "under-investigation"
    _, _, unresolved, _ = RADAR.evaluate(index, unresolved_metadata)
    assert unresolved == ["2026-4"]

    with tempfile.TemporaryDirectory() as directory:
        profile_root = pathlib.Path(directory)
        for source in (ROOT / "port/hostap").glob("*.toml"):
            (profile_root / source.name).write_bytes(source.read_bytes())
        personal = profile_root / "personal.toml"
        personal.write_text(
            personal.read_text().replace(
                '  "wpa_supplicant/config.c",',
                '  "wpa_supplicant/config.c",\n  "wpa_supplicant/mesh_rsn.c",',
            )
        )
        expect_failure(
            lambda: RADAR.validate_metadata(metadata, profile_root),
            "adding the affected mesh source must invalidate not-affected",
        )

    print("hostap security radar contract tests: PASS (5 cases)")


if __name__ == "__main__":
    main()
