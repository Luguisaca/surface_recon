"""Minimal capability availability/applicability contract."""

from dataclasses import dataclass
from typing import Callable

from .model import AvailabilityState, Capability, Limitation, Target


Applicability = Callable[[Target], bool]


@dataclass(slots=True)
class CapabilityDefinition:
    id: str
    availability: AvailabilityState
    applies_to: Applicability
    requirements: tuple[str, ...] = ()
    action_kind: str = "recon"

    def consider(self, target: Target) -> tuple[Capability, Limitation | None]:
        if self.action_kind in {"exploit", "destructive"}:
            raise ValueError("unsafe capability action is not permitted")
        target.require_authorized()
        applicable = self.applies_to(target)
        capability = Capability(
            id=self.id,
            availability=self.availability,
            applicable=applicable,
            requirements=list(self.requirements),
            target_id=target.id,
        )
        limitation = None
        if applicable and self.availability is not AvailabilityState.AVAILABLE:
            limitation = Limitation(
                target_id=target.id,
                capability_id=self.id,
                reason=f"Capability is {self.availability.value}.",
                impact="Applicable evaluation was not completed; absence of risk cannot be inferred.",
            )
        return capability, limitation


def applicable_capabilities(target: Target) -> list[Capability]:
    """Select needed capabilities and derive availability from real tooling."""
    from .tooling import candidates_for, discover_tools

    mapping = {
        # Deeper validation classes are added later only when observed
        # evidence creates a relevant hypothesis for this target.
        "url": (("http-recon", ("http-probing", "technology-fingerprinting", "template-detection", "content-discovery", "error-handling-analysis", "input-surface-analysis")),),
        "host": (("host-recon", ("host-discovery", "port-discovery", "service-fingerprinting")),),
        "network": (("host-recon", ("host-discovery", "port-discovery", "service-fingerprinting")),),
        "path": (("artifact-recon", ("artifact-identification", "metadata-analysis", "static-analysis")),),
        "directory": (("directory-recon", ("inventory", "secret-detection", "dependency-analysis")),),
        "repository": (("repository-recon", ("inventory", "secret-detection", "dependency-analysis", "static-analysis")),),
        "binary": (("binary-recon", ("binary-identification", "metadata-analysis", "static-analysis")),),
        "opaque": (("generic-recon", ("target-characterization", "active-reconnaissance")),),
    }

    selected = []
    for capability_id, required_subcapabilities in mapping.get(target.target_type, ()):
        discovered = discover_tools(capability_id)
        candidates = candidates_for(capability_id)
        # URL reconnaissance has an owned core implementation; external tooling
        # enriches it but is not required for availability.
        core_available = (
            (target.target_type == "url" and capability_id == "http-recon")
            or (target.target_type in {"path", "binary"} and capability_id in {"artifact-recon", "binary-recon"})
            or (target.target_type in {"directory", "repository"} and capability_id in {"directory-recon", "repository-recon"})
            or (target.target_type in {"host", "network"} and capability_id == "host-recon")
            or (target.target_type == "opaque" and capability_id == "generic-recon")
        )
        selected.append(
            Capability(
                id=capability_id,
                availability=(
                    AvailabilityState.AVAILABLE
                    if core_available or discovered
                    else AvailabilityState.UNAVAILABLE
                ),
                applicable=True,
                requirements=[candidate.id for candidate in candidates],
                required_subcapabilities=list(required_subcapabilities),
                target_id=target.id,
            )
        )
    return selected
