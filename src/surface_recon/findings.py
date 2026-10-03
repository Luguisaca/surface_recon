"""Finding construction and traceability."""

from typing import Any

from .model import Evidence, Finding, FindingStatus, Observation
from .redaction import minimize


def build_finding(
    *,
    target_id: str,
    description: str,
    observations: list[Observation],
    evidence: list[Evidence],
    sufficient_evidence: bool,
) -> Finding:
    status = (
        FindingStatus.SUPPORTED
        if sufficient_evidence and evidence
        else FindingStatus.POTENTIAL
    )

    return Finding(
        id=f"finding-{target_id}-{len(observations)}",
        target_id=target_id,
        description=description,
        status=status,
        observation_ids=[item.id for item in observations],
        evidence_ids=[item.id for item in evidence],
        context=(
            "Supported by observable evidence."
            if status is FindingStatus.SUPPORTED
            else "Potential/unconfirmed; evidence is insufficient."
        ),
    )


def findings_from_capability_result(
    *,
    target_id: str,
    capability_id: str,
    observations: list[dict[str, Any]],
) -> tuple[list[Finding], list[Observation], list[Evidence]]:
    normalized_observations: list[Observation] = []
    normalized_evidence: list[Evidence] = []
    finding_groups: dict[str, list[tuple[dict[str, Any], Observation]]] = {}

    for index, raw in enumerate(observations, start=1):
        observation_id = f"{target_id}-observation-{index}"
        evidence_ids: list[str] = []

        raw_evidence = raw.get("evidence")
        if raw_evidence is not None:
            evidence_id = f"{target_id}-evidence-{index}"
            normalized_evidence.append(
                Evidence(
                    id=evidence_id,
                    source=raw.get("source", capability_id),
                    content=minimize(raw_evidence),
                )
            )
            evidence_ids.append(evidence_id)

        observation = Observation(
            id=observation_id,
            target_id=target_id,
            capability_id=capability_id,
            description=str(minimize(raw["description"])),
            context="Capability observation.",
            evidence_ids=evidence_ids,
        )
        normalized_observations.append(observation)

        if raw.get("finding", True):
            key = raw.get("correlation_key") or raw["description"]
            finding_groups.setdefault(str(key), []).append((raw, observation))

    findings: list[Finding] = []
    evidence_by_id = {item.id: item for item in normalized_evidence}
    for group in finding_groups.values():
        raw_items = [item[0] for item in group]
        grouped_observations = [item[1] for item in group]
        evidence_ids = [
            evidence_id
            for observation in grouped_observations
            for evidence_id in observation.evidence_ids
        ]
        grouped_evidence = [
            evidence_by_id[evidence_id]
            for evidence_id in evidence_ids
            if evidence_id in evidence_by_id
        ]
        findings.append(
            build_finding(
                target_id=target_id,
                description=str(minimize(raw_items[0]["description"])),
                observations=grouped_observations,
                evidence=grouped_evidence,
                sufficient_evidence=bool(grouped_evidence),
            )
        )

    return findings, normalized_observations, normalized_evidence
