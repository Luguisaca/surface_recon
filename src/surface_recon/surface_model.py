"""Semantic attack-surface normalization.

Raw observations remain immutable evidence. This module builds a compact semantic
view so multiple providers/owned probes enrich one endpoint instead of becoming
separate human-facing surface items.
"""
from __future__ import annotations

from typing import Any


def service_key(host: str, port: int, protocol: str = "tcp") -> str:
    return f"{host}:{int(port)}/{protocol or 'tcp'}"


def merge_service_surface(observations: list[dict[str, Any]], default_host: str) -> list[dict[str, Any]]:
    services: dict[str, dict[str, Any]] = {}
    current_evidence_id = None

    def merge(host: str, port: int, protocol: str, evidence: dict[str, Any], source: str, level: int) -> None:
        key = service_key(host, port, protocol)
        row = services.setdefault(key, {
            "type": "network-service", "value": key,
            "host": host, "port": int(port), "protocol": protocol or "tcp",
            "service": None, "product": None, "version": None,
            "evidence_sources": [], "evidence": [],
            "evidence_ids": [],
            "identity_confidence": "reachable",
            "why": "Network endpoint observed reachable.",
        })
        if source not in row["evidence_sources"]:
            row["evidence_sources"].append(source)
        row["evidence"].append(evidence)
        if current_evidence_id and current_evidence_id not in row["evidence_ids"]:
            row["evidence_ids"].append(current_evidence_id)
        for field in ("service", "product", "version"):
            value = evidence.get(field) or (evidence.get("service_hint") if field == "service" else None)
            if value and not row.get(field):
                row[field] = value
        if level >= 2:
            row["identity_confidence"] = "fingerprinted"
            row["why"] = "Reachable endpoint enriched with protocol/service fingerprint evidence."
        elif level >= 1 and row["identity_confidence"] == "reachable":
            row["identity_confidence"] = "provider-hint"
            row["why"] = "Reachable endpoint enriched with a provider service hint; identity is not yet a verified fingerprint."

    for observation in observations:
        current_evidence_id = observation.get("evidence_id")
        data = observation.get("evidence") if isinstance(observation, dict) else None
        if not isinstance(data, dict):
            continue
        kind = data.get("kind")
        source = str(observation.get("source") or "unknown")
        if kind == "ports":
            host = str(data.get("host") or default_host)
            for item in data.get("reachable", []):
                merge(host, int(item.get("port") or 0), "tcp", item, source, 0)
        elif kind == "service-fingerprints":
            host = str(data.get("host") or default_host)
            for item in data.get("services", []):
                level = 2 if item.get("banner") else 0
                merge(host, int(item.get("port") or 0), "tcp", item, source, level)
        elif kind == "nmap-surface":
            for host_row in data.get("hosts", []):
                host = str((host_row.get("addresses") or [default_host])[0])
                for item in host_row.get("services", []):
                    fingerprinted = bool(item.get("product") or item.get("version") or item.get("method") == "probed")
                    merge(host, int(item.get("port") or 0), str(item.get("protocol") or "tcp"), item, source, 2 if fingerprinted else 1)
    return list(services.values())


_SERVICE_FAMILIES = {
    "remote-access": {"ssh", "rdp"},
    "file-sharing": {"smb", "microsoft-ds", "netbios-ssn"},
    "database": {"mysql", "mariadb", "postgresql", "ms-sql-s", "mongodb", "redis"},
    "web": {"http", "https", "http-alt", "http-proxy", "ssl/http"},
    "rpc": {"msrpc", "rpcbind", "sunrpc"},
}


def prioritize_service_surface(surface: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add explainable review priority without converting exposure into a vulnerability."""
    output = []
    for original in surface:
        row = dict(original)
        name = str(row.get("service") or "").lower()
        family = next((family for family, names in _SERVICE_FAMILIES.items() if name in names), "unknown")
        confidence = row.get("identity_confidence")
        if family in {"database", "remote-access", "file-sharing", "rpc"} and confidence == "fingerprinted":
            priority, reason = "high", f"{family} interface is reachable and fingerprinted; validate intended exposure and security boundary."
        elif family == "web":
            priority, reason = "high", "HTTP-family service is reachable; pivot into application-layer reconnaissance."
        elif confidence == "fingerprinted":
            priority, reason = "medium", "Service identity has fingerprint evidence; evaluate protocol-specific exposure."
        else:
            priority, reason = "medium", "Endpoint is reachable but identity is incomplete; fingerprint before protocol-specific conclusions."
        row["service_family"] = family
        row["review_priority"] = priority
        row["priority_reason"] = reason
        output.append(row)
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(output, key=lambda x: (order.get(str(x.get("review_priority")), 9), x["value"]))
