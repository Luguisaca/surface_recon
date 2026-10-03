"""Evidence-driven interpretation of reconnaissance responses.

This module does not prove exploitability. It converts directly observed
response evidence into narrowly-scoped findings or validation hypotheses.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


_STACK_FRAME = re.compile(r"\bat\s+[^<\n]*?(?:\([^\n<)]*:\d+:\d+\)|[^<\n ]*:\d+:\d+)")
_UNIX_INTERNAL_PATH = re.compile(r"/[A-Za-z0-9_.@+-]+(?:/[A-Za-z0-9_.@+-]+){2,}\.(?:js|ts|py|rb|php|java)(?::\d+(?::\d+)?)?")
_WINDOWS_INTERNAL_PATH = re.compile(r"[A-Za-z]:\\(?:[^\s<>:'\"()]+\\){2,}[^\s<>:'\"()]+\.(?:js|ts|py|rb|php|java)(?::\d+(?::\d+)?)?")


def interpret_http_response(
    *,
    url: str,
    status: int,
    headers: dict[str, str],
    body: bytes,
    discovered_from: str | None = None,
) -> list[dict[str, Any]]:
    """Return evidence-backed interpretations for one observed HTTP response."""
    text = body.decode("utf-8", errors="replace")
    observations: list[dict[str, Any]] = []
    content_type = headers.get("Content-Type", "").lower()
    # Bound expensive document interpretation on multi-megabyte client bundles.
    document_like = any(token in content_type for token in ("html", "text/plain", "xml")) or status >= 400
    document_text = text[:250_000] if document_like else ""

    frames = _STACK_FRAME.findall(document_text)
    paths = list(dict.fromkeys(
        _UNIX_INTERNAL_PATH.findall(document_text) + _WINDOWS_INTERNAL_PATH.findall(document_text)
    ))
    # Require multiple independent implementation-detail signals. A single
    # occurrence of "at" or a path-like string is not enough to call a finding.
    verbose_error = len(frames) >= 2 or (frames and paths)
    if verbose_error:
        excerpt_lines = list(dict.fromkeys(
            [frame.strip() for frame in frames] + paths
        ))[:12]
        observations.append({
            "description": "Verbose error response exposes internal implementation details",
            "correlation_key": "verbose-error-information-disclosure",
            "finding": True,
            "source": "surface-recon-interpreter",
            "evidence": {
                "kind": "security-finding",
                "classification": "information-disclosure",
                "url": url,
                "status": status,
                "content_type": headers.get("Content-Type", ""),
                "cwe": "CWE-209",
                "owasp": "OWASP Top 10 2025 A10: Mishandling of Exceptional Conditions",
                "wstg": "WSTG-ERRH-02",
                "confidence": "high",
                "basis": "Multiple server-side stack-frame/internal-path signals were returned to the client.",
                "stack_frames_observed": len(frames),
                "internal_paths": paths[:12],
                "evidence_excerpt": excerpt_lines,
                "discovered_from": discovered_from,
                "impact_demonstrated": "Internal implementation details disclosed; no additional exploit impact demonstrated.",
                "validation": {
                    "goal": "Confirm whether equivalent error handling exposes implementation details on related endpoints.",
                    "safe_reproduction": ["curl", "-i", url],
                    "preserve": ["request", "response", "timestamp", "endpoint", "status"],
                    "human_gate": "Any mutation, bypass, injection, or exploit attempt requires explicit authorized testing scope.",
                },
            },
        })

    listing_signals = [
        bool(re.search(r"<title>\s*(?:index of|listing directory)\b", document_text, re.IGNORECASE)),
        bool(re.search(r"<h1[^>]*>.*(?:index of|/\s*</h1>)", document_text, re.IGNORECASE | re.DOTALL)),
        bool(re.search(r"(?:id|class)=[\"'][^\"']*(?:files|directory-listing)[^\"']*[\"']", document_text, re.IGNORECASE)),
    ]
    if status < 400 and sum(listing_signals) >= 2:
        hrefs = list(dict.fromkeys(re.findall(r"<a\s+[^>]*href=[\"']([^\"']+)[\"']", document_text, re.IGNORECASE)))
        risky = [x for x in hrefs if re.search(r"(?i)(?:\.bak|\.old|\.backup|\.kdbx|\.key|\.pem|\.sql|\.pyc)(?:$|[?#])", x)]
        observations.append({
            "description": "Browsable directory listing exposes server-side file inventory",
            "correlation_key": "directory-listing-exposure",
            "finding": True,
            "source": "surface-recon-interpreter",
            "evidence": {
                "kind": "security-finding",
                "classification": "directory-listing",
                "url": url,
                "status": status,
                "content_type": headers.get("Content-Type", ""),
                "cwe": "CWE-548",
                "confidence": "high",
                "basis": "Multiple independent directory-index markers are present in the returned HTML.",
                "entries_observed": len(hrefs),
                "sample_entries": hrefs[:20],
                "potentially_sensitive_entries": risky[:20],
                "impact_demonstrated": "Server-side file names are enumerable through a browsable directory index; file contents were not automatically retrieved to prove additional impact.",
                "validation": {
                    "goal": "Confirm the directory index is reachable in the intended assessment context and review exposed names before selectively validating files.",
                    "safe_reproduction": ["curl", "-i", url],
                    "preserve": ["request", "response", "timestamp", "directory URL", "listed entries"],
                    "human_gate": "Retrieving sensitive-looking files or attempting bypasses remains an explicit authorized testing decision.",
                },
            },
        })

    # Input-bearing surfaces create actionable validation hypotheses, never
    # vulnerability claims. Recipes are deliberately tool-agnostic so another
    # evidence/test system (for example TATACOA) can execute them later.
    parsed = urlparse(url)
    query_names = list(dict.fromkeys(
        match.group(1) for match in re.finditer(r"(?:^|&)([^=&]+)=", parsed.query)
    ))
    if query_names:
        observations.append({
            "description": "User-controllable query input observed; injection classes require validation",
            "finding": False,
            "source": "surface-recon-interpreter",
            "evidence": {
                "kind": "security-hypothesis",
                "hypothesis": "input-validation",
                "url": url,
                "status": status,
                "parameters": query_names,
                "candidate_classes": ["SQL injection", "cross-site scripting", "server-side injection"],
                "confidence": "candidate-surface",
                "reason": "The observed endpoint accepts query parameters; no injection vulnerability has been demonstrated.",
                "validation_recipe": {
                    "target": url,
                    "method": "GET",
                    "inputs": query_names,
                    "checks": [
                        {"class": "SQL injection", "objective": "Compare baseline and controlled input variants for database-error, boolean, or timing evidence."},
                        {"class": "cross-site scripting", "objective": "Determine whether a unique benign marker is reflected and in which HTML/DOM context before any executable payload is considered."},
                        {"class": "server-side injection", "objective": "Compare controlled metacharacter variants only when endpoint semantics justify server-side interpretation."},
                    ],
                    "success_rule": "Promote only when response/runtime evidence demonstrates the class; otherwise retain as hypothesis.",
                    "preserve": ["baseline request/response", "variant request/response", "timing", "parameter", "context"],
                },
            },
        })

    forms = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", document_text, re.IGNORECASE | re.DOTALL):
        attrs, inner = match.groups()
        action_match = re.search(r"\baction=[\"']([^\"']*)[\"']", attrs, re.IGNORECASE)
        method_match = re.search(r"\bmethod=[\"']([^\"']*)[\"']", attrs, re.IGNORECASE)
        names = list(dict.fromkeys(re.findall(r"<(?:input|textarea|select)\b[^>]*\bname=[\"']([^\"']+)[\"']", inner, re.IGNORECASE)))
        if names:
            forms.append({
                "action": action_match.group(1) if action_match else url,
                "method": (method_match.group(1) if method_match else "GET").upper(),
                "inputs": names,
            })
    for form in forms:
        observations.append({
            "description": "HTML form exposes user-controlled input surface",
            "finding": False,
            "source": "surface-recon-interpreter",
            "evidence": {
                "kind": "security-hypothesis",
                "hypothesis": "form-input-validation",
                "url": url,
                "status": status,
                "form": form,
                "candidate_classes": ["SQL injection", "cross-site scripting", "server-side validation weakness"],
                "confidence": "candidate-surface",
                "reason": "A form accepts named user inputs; vulnerability behavior has not been demonstrated.",
                "validation_recipe": {
                    "target": form["action"],
                    "method": form["method"],
                    "inputs": form["inputs"],
                    "checks": [
                        {"class": "SQL injection", "objective": "Establish a baseline then compare controlled input variants for database-backed behavior."},
                        {"class": "cross-site scripting", "objective": "Use a unique benign marker first to determine reflection/storage and output context."},
                    ],
                    "success_rule": "Require reproducible response/runtime evidence before promoting a finding.",
                    "preserve": ["baseline request/response", "variant request/response", "input name", "output context"],
                },
            },
        })

    path_lower = parsed.path.lower()
    if re.search(r"/(?:admin|account|user|users|profile|order|orders|basket|cart|invoice|document|file)(?:/|$)", path_lower):
        observations.append({
            "description": "Identity- or object-sensitive route observed; authorization boundaries require validation",
            "finding": False,
            "source": "surface-recon-interpreter",
            "evidence": {
                "kind": "security-hypothesis",
                "hypothesis": "authorization-boundary",
                "url": url,
                "status": status,
                "candidate_classes": ["broken access control", "IDOR/BOLA"],
                "confidence": "candidate-surface",
                "reason": "Route semantics indicate identity, privileged function, or object access; no authorization bypass has been demonstrated.",
                "validation_recipe": {
                    "target": url,
                    "checks": [
                        {"class": "broken access control", "objective": "Compare the same operation across unauthenticated and distinct authorized identities without exceeding their intended privileges."},
                        {"class": "IDOR/BOLA", "objective": "Where an object identifier exists, compare access to an owned object and a separately authorized test object's identifier."},
                    ],
                    "success_rule": "Promote only when an identity can reproducibly access an operation/object outside its intended authorization.",
                    "preserve": ["identity/role", "request", "response", "object identifier", "expected authorization"],
                },
            },
        })

    return observations
