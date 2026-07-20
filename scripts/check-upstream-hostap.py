#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Verify the pinned upstream hostap source and supplicant ABI contract."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "upstream/hostap-2.11.json"
ARTIFACT_MANIFEST = (
    ROOT / "crates/ws63-radio-blob/artifacts/manifest.json"
)


def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", ROOT / "third-party/hostap", *args], text=True
    ).strip()


def tagged_commit(tag: str) -> str:
    try:
        return git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    except subprocess.CalledProcessError:
        # actions/checkout recursively fetches the pinned submodule commit but
        # may omit tag refs. Verify the immutable upstream tag instead of
        # treating a shallow checkout as source drift.
        output = git(
            "ls-remote",
            "--exit-code",
            "origin",
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        )
        refs = dict(
            line.split("\t", 1)[::-1]
            for line in output.splitlines()
            if "\t" in line
        )
        return refs.get(f"refs/tags/{tag}^{{}}", refs.get(f"refs/tags/{tag}", ""))


def require_commit(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise SystemExit(f"invalid hostap {field} commit")
    return value


def require_ancestor(ancestor: str, descendant: str, label: str) -> None:
    result = subprocess.run(
        [
            "git",
            "-C",
            ROOT / "third-party/hostap",
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ],
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"hostap {label} {ancestor} is not in {descendant}")


def main() -> int:
    metadata = json.loads(MANIFEST.read_text())
    if metadata["schema"] != "hispark-rs/upstream-hostap/v2":
        raise SystemExit("unsupported hostap source manifest schema")
    if metadata["upstream_repository"] != "https://git.w1.fi/hostap.git":
        raise SystemExit("hostap upstream repository drift")
    if metadata["repository"] != "https://github.com/hispark-rs/hostap.git":
        raise SystemExit("hostap source mirror drift")
    submodule_url = subprocess.check_output(
        [
            "git",
            "config",
            "-f",
            ROOT / ".gitmodules",
            "--get",
            "submodule.third-party/hostap.url",
        ],
        text=True,
    ).strip()
    if submodule_url != metadata["repository"]:
        raise SystemExit("hostap .gitmodules URL drift")
    if git("remote", "get-url", "origin") != metadata["repository"]:
        raise SystemExit("hostap checkout origin drift")
    actual = git("rev-parse", "HEAD")
    expected = require_commit(metadata["commit"], "pinned")
    if actual != expected:
        raise SystemExit(f"hostap submodule drift: expected {expected}, got {actual}")

    base = require_commit(metadata["base_commit"], "base")
    tag_commit = tagged_commit(metadata["tag"])
    if tag_commit != base:
        raise SystemExit(
            f"hostap tag {metadata['tag']} drift: expected {base}, "
            f"got {tag_commit or 'missing'}"
        )
    require_ancestor(base, expected, "release base")

    advisories: set[str] = set()
    applied_commits: list[str] = []
    for backport in metadata["security_backports"]:
        advisory = backport["advisory"]
        if not re.fullmatch(r"20[0-9]{2}-[0-9]+", advisory):
            raise SystemExit(f"invalid hostap advisory id: {advisory!r}")
        if advisory in advisories:
            raise SystemExit(f"duplicate hostap advisory: {advisory}")
        advisories.add(advisory)
        if backport["url"] != f"https://w1.fi/security/{advisory}/":
            raise SystemExit(f"hostap advisory URL drift: {advisory}")
        commits = backport["applied_commits"]
        if not commits:
            raise SystemExit(f"hostap advisory has no applied commits: {advisory}")
        for index, commit in enumerate(commits):
            commit = require_commit(commit, f"{advisory}[{index}]")
            if commit in applied_commits:
                raise SystemExit(f"duplicate hostap security commit: {commit}")
            applied_commits.append(commit)
            require_ancestor(commit, expected, f"security backport {advisory}")

    actual_backports = git("rev-list", "--reverse", f"{base}..{expected}").splitlines()
    if actual_backports != applied_commits:
        raise SystemExit(
            "hostap security history drift: "
            f"manifest={applied_commits}, actual={actual_backports}"
        )

    version_header = (
        ROOT / "third-party/hostap/src/common/version.h"
    ).read_text()
    match = re.search(r'#define VERSION_STR "([^"]+)"', version_header)
    if not match or match.group(1) != metadata["version"]:
        raise SystemExit("hostap VERSION_STR does not match the source manifest")

    digest = metadata["release_archive"]["sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit("invalid release archive SHA-256")

    artifact_metadata = json.loads(ARTIFACT_MANIFEST.read_text())
    artifact_upstream = artifact_metadata["native_supplicant"]["upstream"]
    expected_artifact_upstream = {
        "version": metadata["version"],
        "tag": metadata["tag"],
        "base_commit": base,
        "commit": expected,
        "security_advisories": sorted(
            advisories,
            key=lambda value: tuple(int(part) for part in value.split("-")),
        ),
        "release_archive_sha256": digest,
    }
    if artifact_upstream != expected_artifact_upstream:
        raise SystemExit(
            "hostap Cargo artifact provenance drift: "
            f"expected={expected_artifact_upstream}, actual={artifact_upstream}"
        )
    print(
        f"hostap {metadata['version']} base={base} patched={actual}; "
        f"advisories={','.join(sorted(advisories))}; release sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
