"""Read explicit installed metadata and explain overlapping ownership claims."""

from __future__ import annotations

import argparse
import configparser
import csv
import io
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from email.parser import Parser
from pathlib import Path

__version__ = "0.1.0"


@dataclass(frozen=True)
class Limits:
    metadata_bytes: int = 8 * 1024 * 1024
    total_bytes: int = 64 * 1024 * 1024
    claims: int = 500_000
    distributions: int = 10_000
    findings: int = 1_000


class MetadataError(ValueError):
    """The requested metadata cannot be completely inspected."""


def _linked(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def _canonical(root: Path, recorded: str, insensitive: bool) -> str:
    if not recorded or any(ord(c) < 32 or ord(c) == 127 for c in recorded):
        raise MetadataError("empty or control-character RECORD path")
    # Lexical only: RECORD may legitimately refer to ../Scripts. Never open this path.
    value = os.path.abspath(os.path.join(root, recorded.replace("/", os.sep)))
    return value.casefold() if insensitive else value


class _Reader:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.total = 0

    def text(self, directory: Path, name: str) -> str:
        path = directory / name
        if _linked(path) or path.resolve().parent != directory:
            raise MetadataError(f"linked metadata file: {name}")
        if not path.is_file():
            raise MetadataError(f"missing or non-regular metadata file: {name}")
        remaining = min(self.limits.metadata_bytes, self.limits.total_bytes - self.total)
        if remaining < 0:
            raise MetadataError("total metadata byte budget exceeded")
        with path.open("rb") as stream:
            raw = stream.read(remaining + 1)
        self.total += len(raw)
        if len(raw) > remaining:
            raise MetadataError("metadata byte budget exceeded")
        return raw.decode("utf-8-sig")


def audit(
    sites: list[Path], *, case_insensitive: bool | None = None, limits: Limits | None = None
) -> dict:
    """Audit .dist-info claims; no package imports, payload reads, or filesystem changes."""
    limits = limits or Limits()
    if min(vars(limits).values()) < 1:
        raise ValueError("all limits must be positive")
    insensitive = os.name == "nt" if case_insensitive is None else case_insensitive
    reader = _Reader(limits)
    roots = sorted({Path(site).resolve() for site in sites})
    if not roots or any(not p.is_dir() for p in roots):
        raise ValueError("each --site must be an existing directory")
    findings: list[dict] = []
    finding_count = 0
    complete = True
    owners: list[dict] = []
    files: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
    commands: dict[str, list[dict]] = defaultdict(list)
    names: dict[str, list[str]] = defaultdict(list)
    claim_count = 0
    attempted = 0

    def emit(code: str, **details):
        nonlocal finding_count
        finding_count += 1
        if len(findings) < limits.findings:
            findings.append({"code": code, **details})

    def gap(owner: str, reason: str):
        nonlocal complete
        complete = False
        emit("coverage-gap", owner=owner, reason=reason)

    for index, root in enumerate(roots, 1):
        for directory in sorted(root.iterdir()):
            if directory.name.endswith(".egg-info"):
                gap(f"site{index}/{directory.name}", "legacy egg-info is unsupported")
                continue
            if not directory.name.endswith(".dist-info"):
                continue
            attempted += 1
            if attempted > limits.distributions:
                gap("scan", "distribution count budget exceeded")
                break
            owner = f"site{index}/{directory.name}"
            if _linked(directory) or not directory.is_dir():
                gap(owner, "dist-info must be a regular directory, not a link")
                continue
            try:
                metadata = Parser().parsestr(reader.text(directory, "METADATA"), headersonly=True)
                name, version = metadata.get("Name", ""), metadata.get("Version", "")
                if (
                    len(metadata.get_all("Name", [])) != 1
                    or len(metadata.get_all("Version", [])) != 1
                    or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name)
                    or not version
                    or any(ord(c) < 32 or ord(c) == 127 for c in version)
                ):
                    raise MetadataError("METADATA requires one valid Name and one Version")
                owners.append({"id": owner, "name": name, "version": version})
                names[re.sub(r"[-_.]+", "-", name).lower()].append(owner)
            except (OSError, UnicodeError, MetadataError) as exc:
                gap(
                    owner,
                    f"METADATA: {exc if isinstance(exc, MetadataError) else type(exc).__name__}",
                )
            try:
                record = reader.text(directory, "RECORD")
                local: dict[str, tuple[str, str]] = {}
                rows = csv.reader(io.StringIO(record, newline=""), strict=True)
                for row in rows:
                    claim_count += 1
                    if claim_count > limits.claims:
                        raise MetadataError("RECORD claim count budget exceeded")
                    if len(row) != 3:
                        raise MetadataError("RECORD rows must contain exactly three columns")
                    recorded, digest, size = row
                    key = _canonical(root, recorded, insensitive)
                    if digest and not re.fullmatch(r"[\w+-]+=[A-Za-z0-9_-]+", digest, re.ASCII):
                        raise MetadataError("invalid recorded hash syntax")
                    if size and not re.fullmatch(r"[0-9]+", size):
                        raise MetadataError("invalid recorded size")
                    if key in local:
                        emit("duplicate-record-path", owner=owner, path=key)
                    local[key] = (digest, size)
                if not local:
                    raise MetadataError("empty RECORD")
                for key, value in local.items():
                    files[key][owner] = value
            except (OSError, UnicodeError, csv.Error, MetadataError) as exc:
                gap(
                    owner,
                    f"RECORD: {exc if isinstance(exc, MetadataError) else type(exc).__name__}",
                )
            ep = directory / "entry_points.txt"
            if not ep.exists() and not ep.is_symlink():
                continue
            try:
                parser = configparser.ConfigParser(
                    interpolation=None, delimiters=("=",), strict=True
                )
                parser.optionxform = str
                parser.read_string(reader.text(directory, "entry_points.txt"))
                for group in ("console_scripts", "gui_scripts"):
                    if not parser.has_section(group):
                        continue
                    for name, target in parser.items(group):
                        if (
                            not name
                            or name in {".", ".."}
                            or any(c in name for c in "/\\:")
                            or any(c.isspace() or ord(c) < 32 for c in name)
                            or not target
                        ):
                            raise MetadataError("invalid command entry point")
                        key = name.casefold() if insensitive else name
                        commands[key].append({"owner": owner, "group": group, "name": name})
            except (OSError, UnicodeError, configparser.Error, MetadataError) as exc:
                gap(
                    owner,
                    f"entry_points.txt: {exc if isinstance(exc, MetadataError) else type(exc).__name__}",
                )
        if attempted > limits.distributions or claim_count > limits.claims:
            break
    if not attempted:
        gap("scan", "no dist-info metadata found in the supplied directories")
    for name, claims in sorted(names.items()):
        if len(claims) > 1:
            emit("duplicate-distribution", name=name, owners=claims)
    for path, claims in sorted(files.items()):
        if len(claims) < 2:
            continue
        algorithms: dict[str, set[str]] = defaultdict(set)
        sizes = {size for _, size in claims.values() if size}
        for digest, _ in claims.values():
            if digest:
                algorithm, encoded = digest.split("=", 1)
                algorithms[algorithm].add(encoded)
        disagree = sorted(algorithm for algorithm, values in algorithms.items() if len(values) > 1)
        emit(
            "shared-file",
            path=path,
            owners=sorted(claims),
            different_hash_algorithms=disagree,
            different_recorded_sizes=len(sizes) > 1,
        )
    for name, claims in sorted(commands.items()):
        if len(claims) > 1:
            emit("shared-command", command=name, claims=claims)
    return {
        "schema_version": 1,
        "tool_version": __version__,
        "complete": complete,
        "case_insensitive": insensitive,
        "sites": [str(p) for p in roots],
        "distributions": owners,
        "record_rows": claim_count,
        "finding_count": finding_count,
        "findings_truncated": finding_count > len(findings),
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "--site",
        type=Path,
        action="append",
        required=True,
        help="explicit site-packages directory; repeatable",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--case-insensitive", action="store_true", default=None)
    group.add_argument("--case-sensitive", dest="case_insensitive", action="store_false")
    parser.add_argument("--json", action="store_true", help="emit the versioned JSON report")
    args = parser.parse_args(argv)
    try:
        report = audit(args.site, case_insensitive=args.case_insensitive)
    except (OSError, ValueError) as exc:
        print(
            json.dumps({"error": type(exc).__name__, "message": str(exc)}, ensure_ascii=True),
            file=sys.stderr,
        )
        return 2
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        print(
            f"{len(report['distributions'])} distributions; {report['finding_count']} findings; complete={report['complete']}"
        )
        for finding in report["findings"]:
            print(json.dumps(finding, ensure_ascii=True))
    return 2 if not report["complete"] else int(report["finding_count"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
