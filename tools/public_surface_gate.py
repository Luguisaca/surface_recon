"""Fail closed on unsuitable public paths, sensitive content and PR metadata.

This gate is deliberately provider-independent for local checks; when running in
GitHub Actions it also inspects pull-request metadata and existing discussion.
It reports file/line and rule names only, never suspected secret values.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_EXACT = {"AGENTS.md"}
FORBIDDEN_PREFIXES = (".specify/", "specs/", "benchmarks/")
MAX_TEXT_BYTES = 3_000_000

# Avoid false positives for public example domains and generic words such as
# "internal" in program code. Blocks are indicators, not a full secret scanner.
RULES = {
    "private-repository-reference": re.compile(
        r"(?i)(?:surface[_-]recon[_-]internal|github\.com/[\w.-]+/[\w.-]+[_-]internal\b)"
    ),
    "private-workspace-link": re.compile(
        r"(?i)(?:https?://(?:www\.)?(?:app\.notion\.com|notion\.so)/)"
    ),
    "operational-device": re.compile(
        r"(?i)\b(?:" + "PC" + r"[12]|Dell[- ]Server|LUGUISACA[-_]CI[-_]PC[12])\b"
    ),
    "personal-local-path": re.compile(
        r"(?i)\b[a-z]:\\(?:users\\[^\\\s]+|luguisaca(?:\\|[-_]))"
    ),
    "private-governance": re.compile(
        r"(?i)\b" + "INTERNAL" + r"/main\b|\b" + "INTERNAL" + r"\s+(?:PR|repository|repo|handoff|research|specs|evidence)\b"
    ),
    "credential-like-value": re.compile(
        r"(?i)(?:gh[pousr]_[a-z0-9]{28,}|github_pat_[a-z0-9_]{20,}|"
        r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----)"
    ),
}


def scan(text: str, label: str) -> list[str]:
    """Record locations, not the matching strings."""
    findings = []
    for rule, pattern in RULES.items():
        for match in list(pattern.finditer(text))[:12]:
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{label}:{line}: {rule}")
    return findings


def tracked_paths(root: Path) -> list[str]:
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    return [p.decode("utf-8") for p in raw.split(b"\0") if p]


def scan_files(root: Path) -> tuple[list[str], int]:
    findings = []
    paths = tracked_paths(root)
    for rel in paths:
        normalized = rel.replace("\\", "/")
        if normalized in FORBIDDEN_EXACT or normalized.startswith(FORBIDDEN_PREFIXES):
            findings.append(f"{normalized}: forbidden public path")
        p = root / rel
        if not p.is_file():
            findings.append(f"{normalized}: tracked file missing")
            continue
        size = p.stat().st_size
        if size > MAX_TEXT_BYTES:
            findings.append(f"{normalized}: oversized file requires inspection")
            continue
        raw = p.read_bytes()
        if b"\0" in raw[:4096]:
            continue  # Binary file: governed by the existing file-surface policy.
        findings.extend(scan(raw.decode("utf-8", "replace"), normalized))
    return findings, len(paths)


def fetch_comments(url: str, token: str) -> list[dict]:
    comments = []
    for page in range(1, 11):
        suffix = "&" if "?" in url else "?"
        request = Request(
            f"{url}{suffix}per_page=100&page={page}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "surface-recon-public-surface-gate",
            },
        )
        with urlopen(request, timeout=12) as response:
            rows = json.load(response)
        if not isinstance(rows, list):
            raise ValueError("GitHub discussion response was not an array")
        comments.extend(rows)
        if len(rows) < 100:
            return comments
    raise RuntimeError("GitHub discussion pagination exceeded inspection bound")


def scan_event(env: dict[str, str]) -> list[str]:
    path = env.get("GITHUB_EVENT_PATH")
    if not path:
        return []  # Local validation checks tracked files.
    event = json.loads(Path(path).read_text(encoding="utf-8"))
    findings = []
    pr = event.get("pull_request") or event.get("issue", {}).get("pull_request")
    if isinstance(pr, dict):
        for field in ("title", "body"):
            findings.extend(scan(str(pr.get(field) or ""), f"PR.{field}"))
    for field in ("comment", "review"):
        obj = event.get(field) or {}
        if isinstance(obj, dict):
            findings.extend(scan(str(obj.get("body") or ""), field))
    number = event.get("number") or event.get("issue", {}).get("number")
    if pr and number:
        repo = env.get("GITHUB_REPOSITORY", "")
        token = env.get("GITHUB_TOKEN", "")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or not token:
            return findings + ["PR discussion inspection unavailable: missing repository/token"]
        base = f"https://api.github.com/repos/{repo}"
        try:
            for resource in (
                f"/issues/{int(number)}/comments",
                f"/pulls/{int(number)}/comments",
                f"/pulls/{int(number)}/reviews",
            ):
                for item in fetch_comments(base + resource, token):
                    findings.extend(scan(str(item.get("body") or ""), f"PR.discussion[{item.get('id', '?')}]"))
        except (HTTPError, URLError, ValueError, RuntimeError) as exc:
            findings.append(f"PR discussion inspection failed ({type(exc).__name__})")
    return findings


def main() -> int:
    findings, count = scan_files(ROOT)
    findings.extend(scan_event(os.environ))
    if findings:
        print("PUBLIC SURFACE FAIL")
        for finding in findings[:100]:
            print(finding)
        return 1
    print(f"PUBLIC SURFACE PASS ({count} tracked files + available PR metadata checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
