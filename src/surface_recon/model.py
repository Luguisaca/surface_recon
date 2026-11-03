"""Core information model for Surface_Recon."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ScopeState(StrEnum):
    AUTHORIZED = "authorized"
    OUT_OF_SCOPE = "out_of_scope"


class ClassificationState(StrEnum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


class AssessmentStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class AvailabilityState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"


class FindingStatus(StrEnum):
    SUPPORTED = "supported"
    POTENTIAL = "potential/unconfirmed"


@dataclass(slots=True)
class Target:
    id: str
    value: str
    scope_state: ScopeState
    target_type: str | None = None
    classification_state: ClassificationState = ClassificationState.UNRESOLVED
    discovered_resources: list[str] = field(default_factory=list)
    extension_hints: list[str] = field(default_factory=list)
    technology_hints: list[str] = field(default_factory=list)

    def require_authorized(self) -> None:
        if self.scope_state is not ScopeState.AUTHORIZED:
            raise ValueError("Target is not within authorized scope.")


@dataclass(slots=True)
class Capability:
    id: str
    availability: AvailabilityState
    applicable: bool | None = None
    requirements: list[str] = field(default_factory=list)
    status: str | None = None
    tools_used: list[str] = field(default_factory=list)
    required_subcapabilities: list[str] = field(default_factory=list)
    evaluated_subcapabilities: list[str] = field(default_factory=list)
    target_id: str | None = None


@dataclass(slots=True)
class Evidence:
    id: str
    source: str
    content: Any
    redacted: bool = False


@dataclass(slots=True)
class Observation:
    id: str
    target_id: str
    capability_id: str
    description: str
    context: str
    evidence_ids: list[str] = field(default_factory=list)
    redacted: bool = False


@dataclass(slots=True)
class Finding:
    id: str
    target_id: str
    description: str
    status: FindingStatus
    observation_ids: list[str]
    evidence_ids: list[str]
    context: str

    def validate_traceability(self) -> None:
        if not self.observation_ids or not self.evidence_ids:
            raise ValueError("Finding requires supporting observations and evidence.")


@dataclass(slots=True)
class Limitation:
    target_id: str
    reason: str
    impact: str
    capability_id: str | None = None


@dataclass(slots=True)
class Coverage:
    target_id: str
    considered: list[str] = field(default_factory=list)
    evaluated: list[str] = field(default_factory=list)
    unevaluated: list[str] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)


@dataclass(slots=True)
class Assessment:
    id: str
    targets: list[Target]
    status: AssessmentStatus = AssessmentStatus.PENDING
    capabilities: list[Capability] = field(default_factory=list)
    coverage: list[Coverage] = field(default_factory=list)
    limitations: list[Limitation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    def validate_scope(self) -> None:
        for target in self.targets:
            target.require_authorized()
