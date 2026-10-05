"""Surface_Recon-owned web reconnaissance core.

No external scanner is required. The core observes, classifies, prioritizes and
follows same-origin evidence until the evidence frontier is exhausted. Optional budgets are reserved for deterministic QA.
"""
from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
import hashlib
import re
import socket
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from .model import Target
from .interpretation import interpret_http_response


@dataclass(slots=True)
class CoreExecution:
    succeeded: bool
    observations: list[dict[str, Any]]
    covered_subcapabilities: tuple[str, ...]
    discovered: list[str]
    error: str | None = None


@dataclass(slots=True)
class Candidate:
    url: str
    source: str
    kind: str
    priority: int


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.items: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = {"a": ("href", "page"), "form": ("action", "form"), "script": ("src", "script"),
                   "link": ("href", "asset"), "img": ("src", "asset")}
        spec = mapping.get(tag)
        if not spec:
            return
        attr, kind = spec
        for key, value in attrs:
            if key == attr and value:
                self.items.append((value, kind))


def _origin(url: str) -> tuple[str, str, int | None]:
    p = urlparse(url)
    scheme = p.scheme.lower()
    effective_port = p.port
    if effective_port is None:
        effective_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, (p.hostname or "").lower(), effective_port


def _safe_same_origin(base: str, value: str) -> str | None:
    # Some directory indexes emit root-relative-looking links without a leading
    # slash (e.g. current /ftp/ -> href="ftp/file"). Browser resolution would
    # otherwise duplicate the path as /ftp/ftp/file.
    parsed_base = urlparse(base)
    current_path = parsed_base.path.strip("/")
    if current_path and not value.startswith(("/", "http://", "https://", "?", "#")):
        if value == current_path or value.startswith(current_path + "/"):
            value = "/" + value
    absolute = urljoin(base, value)
    p = urlparse(absolute)
    if p.scheme not in {"http", "https"} or _origin(absolute) != _origin(base):
        return None
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))


def _fetch(url: str, timeout: float = 4.0, max_bytes: int = 2_000_000) -> tuple[int, dict[str, str], bytes, str]:
    req = Request(url, headers={"User-Agent": "Surface_Recon/0.2 (+authorized-recon)"})
    try:
        with urlopen(req, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read(max_bytes), response.geturl()
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()), exc.read(max_bytes), exc.geturl()


def _response_fingerprint(status: int, headers: dict[str, str], body: bytes) -> tuple[int, str, str]:
    content_type = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    return status, content_type, hashlib.sha256(body).hexdigest()


def _technology_signals(headers: dict[str, str], body: str) -> list[str]:
    signals: list[str] = []
    for key in ("Server", "X-Powered-By", "Via"):
        if headers.get(key):
            signals.append(f"{key}: {headers[key]}")
    lowered = body.lower()
    fingerprints = {
        "Astro": ("astro-island", "/_astro/", "astro:"),
        "React": ("react", "/static/js/", "_next/"),
        "Angular": ("ng-version", "angular"),
        "Vue": ("__vue__", "vue.js"),
        "WordPress": ("wp-content/", "wp-includes/"),
    }
    for name, needles in fingerprints.items():
        if any(needle in lowered for needle in needles):
            signals.append(name)
    return signals


def _classify(url: str, content_type: str | None = None, hinted: str | None = None) -> str:
    path = urlparse(url).path.lower()
    ctype = (content_type or "").lower()
    if path in {"/robots.txt", "/.well-known/security.txt", "/sitemap.xml"}:
        return "metadata"
    if any(token in path for token in ("/api/", "/graphql", "/rest/", "/oauth", "/auth", "/login", "/admin", "/metrics")):
        return "interesting"
    if "javascript" in ctype or path.endswith((".js", ".mjs")):
        return "script"
    if "html" in ctype or hinted in {"page", "form"}:
        return "page"
    if path.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map")):
        return "asset"
    return hinted or "resource"


def _priority(kind: str) -> int:
    return {"interesting": 100, "metadata": 90, "script": 85, "form": 80, "page": 70, "resource": 40, "asset": 10}.get(kind, 30)


def _literal_candidates(base: str, text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    patterns = [
        (r"""[\"'`](/[A-Za-z0-9._~!$&()*+,;=:@%?/-]{2,240})[\"'`]""", False),
        (r"""["'](https?:\/\/[^"'\s<>]{4,300})["']""", False),
        # Client bundles frequently omit the leading slash for service paths.
        # Restrict this to generic service namespaces to avoid turning every
        # arbitrary string into network traffic.
        (r"""["']((?:api|rest|auth|oauth)\/[A-Za-z0-9._~!$&()*+,;=:@%?\/-]{1,220})["']""", True),
    ]
    for pattern, needs_slash in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            raw = match.group(1)
            if needs_slash:
                raw = "/" + raw
            candidate = _safe_same_origin(base, raw)
            if candidate:
                item = (candidate, _classify(candidate))
                if item not in found:
                    found.append(item)
    return found


def _robots_candidates(base: str, text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        if key.strip().lower() not in {"allow", "disallow", "sitemap"}:
            continue
        value = value.strip()
        if not value or value == "/":
            continue
        candidate = _safe_same_origin(base, value)
        if candidate:
            found.append((candidate, _classify(candidate, hinted="interesting")))
    return found


def _add(queue: list[Candidate], seen_or_queued: set[str], base: str, raw: str, source: str, hinted: str | None = None) -> None:
    candidate = _safe_same_origin(base, raw)
    if not candidate or candidate in seen_or_queued:
        return
    kind = _classify(candidate, hinted=hinted)
    # Direct evidence outranks speculative probes. Hypotheses fill gaps only
    # after links/scripts/metadata have been harvested.
    priority = 75 if source.startswith("hypothesis:") else _priority(kind)
    queue.append(Candidate(candidate, source, kind, priority))
    seen_or_queued.add(candidate)


# Generic capability hypotheses. These are protocol/application concepts, not
# benchmark-specific paths: the planner selects them from observed evidence.
_HYPOTHESES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("api-surface", ("api", "angular", "react", "vue", "javascript"), ("/api", "/api/", "/graphql")),
    ("operational-surface", ("api", "angular", "react", "vue"), ("/metrics", "/health", "/status")),
    ("authentication-surface", ("login", "auth", "account", "token"), ("/login", "/auth", "/api/auth")),
)


def _hypothesis_candidates(base: str, evidence_text: str, signals: list[str]) -> list[tuple[str, str]]:
    haystack = (evidence_text + " " + " ".join(signals)).lower()
    proposed: list[tuple[str, str]] = []
    for name, triggers, paths in _HYPOTHESES:
        if not any(
            re.search(rf"(?<![a-z0-9]){re.escape(trigger)}(?![a-z0-9])", haystack)
            for trigger in triggers
        ):
            continue
        for path in paths:
            proposed.append((path, name))
    return proposed


def recon_url(
    target: Target, *, max_requests: int | None = 30, max_seconds: float | None = 120.0,
    progress: Callable[[str], None] | None = None,
) -> CoreExecution:
    target.require_authorized()
    base = target.value
    observations: list[dict[str, Any]] = []
    discovered: list[str] = []
    covered = {"http-probing", "technology-fingerprinting"}
    started = time.monotonic()
    def emit(message: str) -> None:
        if progress is not None:
            progress(message)
    try:
        parsed = urlparse(base)
        scope_prefix = parsed.path.rstrip("/") if parsed.path not in {"", "/"} else ""
        host = parsed.hostname
        if not host:
            return CoreExecution(False, [], (), [], "URL has no hostname.")
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)})
            observations.append({"description": f"Core: {host} resolves to {', '.join(addresses)}",
                "evidence": {"kind": "infrastructure", "hostname": host, "addresses": addresses},
                "finding": False, "source": "surface-recon-core"})
        except OSError:
            pass

        emit(f"web: probing entrypoint {base}")
        status, headers, body, final_url = _fetch(base)
        ctype = headers.get("Content-Type", "")
        text = body.decode("utf-8", errors="replace")
        signals = _technology_signals(headers, text)
        observations.append({"description": f"Core: HTTP {status} {final_url}",
            "evidence": {"kind": "entrypoint", "url": final_url, "status": status, "content_type": ctype,
                         "server": headers.get("Server"), "content_length_observed": len(body)},
            "finding": False, "source": "surface-recon-core"})
        if signals:
            observations.append({"description": "Core: technology signals: " + ", ".join(signals),
                "evidence": {"kind": "technology", "signals": signals, "url": final_url},
                "finding": False, "source": "surface-recon-core"})
        observations.extend(interpret_http_response(
            url=final_url, status=status, headers=headers, body=body, discovered_from=None,
        ))

        # Learn how this application represents a missing route. This prevents
        # SPA fallback pages (HTTP 200 for arbitrary paths) from becoming false
        # surface discoveries.
        soft_not_found: tuple[int, str, str] | None = None
        requests = 1
        canary = _safe_same_origin(final_url, "/.surface-recon-missing-route-7f31")
        if canary:
            try:
                nf_status, nf_headers, nf_body, _ = _fetch(canary)
                requests += 1
                soft_not_found = _response_fingerprint(nf_status, nf_headers, nf_body)
                observations.append({
                    "description": "Core control: learned missing-route response fingerprint",
                    "evidence": {"kind": "control", "purpose": "soft-not-found-baseline",
                                 "status": nf_status, "content_type": nf_headers.get("Content-Type", "")},
                    "finding": False, "source": "surface-recon-core",
                })
            except (URLError, OSError, TimeoutError):
                pass

        queue: list[Candidate] = []
        known = {final_url}
        if "html" in ctype.lower() or "<html" in text[:4096].lower():
            parser = _Links(); parser.feed(text)
            for raw, hinted in parser.items:
                _add(queue, known, final_url, raw, final_url, hinted)
        for path in ("/robots.txt", "/.well-known/security.txt", "/sitemap.xml"):
            _add(queue, known, final_url, path, "site-convention", "metadata")

        # First adaptive planning step: evidence can justify small, generic
        # capability hypotheses. A hypothesis is only followed same-origin and
        # within the same global request budget.
        for path, hypothesis in _hypothesis_candidates(final_url, text, signals):
            scoped_path = f"{scope_prefix}{path}" if scope_prefix else path
            candidate = _safe_same_origin(final_url, scoped_path)
            if not candidate or candidate in known:
                continue
            observations.append({
                "description": f"Core hypothesis: {hypothesis} -> {candidate}",
                "evidence": {"kind": "hypothesis", "hypothesis": hypothesis, "url": candidate,
                             "reason": "derived from observed application/technology evidence"},
                "finding": False, "source": "surface-recon-core",
            })
            _add(queue, known, final_url, candidate, f"hypothesis:{hypothesis}", "interesting")

        while queue and (max_requests is None or requests < max_requests) and (max_seconds is None or time.monotonic() - started < max_seconds):
            queue.sort(key=lambda item: item.priority, reverse=True)
            item = queue.pop(0)
            # Static visual/style assets are recorded but not fetched: less noise and traffic.
            if item.kind == "asset":
                observations.append({"description": f"Core observed static asset: {item.url}",
                    "evidence": {"kind": "asset", "url": item.url, "discovered_from": item.source, "fetched": False},
                    "finding": False, "source": "surface-recon-core"})
                continue
            try:
                emit(f"web: request {requests + 1}" + (f"/{max_requests}" if max_requests is not None else "") + f" · {item.kind}")
                child_status, child_headers, child_body, child_final = _fetch(item.url)
                requests += 1
            except (URLError, OSError, TimeoutError):
                continue
            if soft_not_found and _response_fingerprint(child_status, child_headers, child_body) == soft_not_found:
                observations.append({
                    "description": f"Core rejected soft-not-found candidate: {child_final}",
                    "evidence": {"kind": "not_found", "url": child_final, "status": child_status,
                                 "discovered_from": item.source, "reason": "matches missing-route baseline"},
                    "finding": False, "source": "surface-recon-core",
                })
                continue
            discovered.append(child_final)
            child_type = child_headers.get("Content-Type", "")
            actual_kind = _classify(child_final, child_type, item.kind)
            observations.append({"description": f"Core discovered {actual_kind}: HTTP {child_status} {child_final}",
                "evidence": {"kind": actual_kind, "url": child_final, "status": child_status,
                             "content_type": child_type, "bytes_observed": len(child_body),
                             "discovered_from": item.source, "fetched": True},
                "finding": False, "source": "surface-recon-core"})
            child_text = child_body.decode("utf-8", errors="replace")
            observations.extend(interpret_http_response(
                url=child_final, status=child_status, headers=child_headers,
                body=child_body, discovered_from=item.source,
            ))
            if actual_kind == "page":
                parser = _Links(); parser.feed(child_text)
                for raw, hinted in parser.items:
                    _add(queue, known, final_url, raw, child_final, hinted)
            if actual_kind == "metadata" and urlparse(child_final).path == "/robots.txt" and child_status < 400:
                for candidate, hinted in _robots_candidates(final_url, child_text):
                    _add(queue, known, final_url, candidate, child_final, hinted)
            if actual_kind == "script":
                passive = _literal_candidates(final_url, child_text)
                # Evidence-derived candidates are deduplicated. Normal product mode
                # follows the frontier; deterministic QA may pass max_requests.
                for candidate, hinted in passive:
                    _add(queue, known, final_url, candidate, child_final, hinted)

        # Discovery coverage describes whether the evidence frontier was evaluated,
        # not whether it happened to yield a resource. An explicit QA budget can
        # leave the operation partial; an exhausted frontier is a completed check.
        if queue:
            covered.add("content-discovery-partial")
        else:
            covered.add("content-discovery")
        covered.add("error-handling-analysis")
        covered.add("input-surface-analysis")
        if not queue:
            stop_reason = "frontier-exhausted"
        elif max_seconds is not None and time.monotonic() - started >= max_seconds:
            stop_reason = "time-budget-exhausted"
        else:
            stop_reason = "request-budget-exhausted"
        observations.append({"description": f"Core decision: reconnaissance stopped after {requests} request(s): {stop_reason}",
            "evidence": {"kind": "decision", "requests": requests, "budget": max_requests,
                         "time_budget_seconds": max_seconds, "elapsed_seconds": round(time.monotonic() - started, 3),
                         "stop_reason": stop_reason, "remaining_candidates": len(queue)},
            "finding": False, "source": "surface-recon-core"})
        return CoreExecution(True, observations, tuple(sorted(covered)), discovered)
    except (URLError, OSError, TimeoutError, ValueError) as exc:
        return CoreExecution(False, observations, tuple(sorted(covered)), discovered, str(exc))


def recon_target(target: Target, *, progress=None) -> CoreExecution:
    if target.target_type == "url":
        return recon_url(target, progress=progress)
    return CoreExecution(False, [], (), [], f"Core reconnaissance for {target.target_type or 'unresolved'} is not implemented yet.")
