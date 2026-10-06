"""Explicit run policy, shared by core and verified adapters without new scanners."""
from contextvars import ContextVar
from dataclasses import dataclass
import time


@dataclass(frozen=True)
class ReconControls:
    profile: str = "auto"
    noise: str = "normal"
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    provider_timeout: int = 300
    pace_ms: int = 100

    def validate(self, *, use_extensions=True):
        from .tooling import adapter_catalog, discover_tools
        if self.profile not in {"auto", "passive", "active", "balanced", "deep"}:
            raise ValueError("Perfil desconocido.")
        if not 0 <= int(self.pace_ms) <= 5000:
            raise ValueError("Pausa fuera de rango: usa 0..5000 ms.")
        if not 30 <= int(self.provider_timeout) <= 3600:
            raise ValueError("Tiempo m?ximo de provider fuera de rango: usa 30..3600 segundos.")
        if self.noise not in {"low", "normal"}:
            raise ValueError("Intensidad desconocida: usa low o normal.")
        catalog = adapter_catalog()
        known = {tool.id for tool in catalog}
        requested = set(self.include) | set(self.exclude)
        if requested - known:
            raise ValueError("Provider sin adapter verificado: " + ", ".join(sorted(requested - known)))
        if set(self.include) & set(self.exclude):
            raise ValueError("Un provider no puede incluirse y excluirse a la vez.")
        if self.include and (not use_extensions or not self.extensions):
            raise ValueError("El perfil/core-only/intensidad seleccionados desactivan los providers solicitados.")
        if self.include:
            verified = {tool.id for cap in {t.capability_id for t in catalog} for tool in discover_tools(cap)}
            if set(self.include) - verified:
                raise ValueError("Provider solicitado no disponible o identidad incompatible: " + ", ".join(sorted(set(self.include) - verified)))

    @property
    def extensions(self):
        return self.profile not in {"passive", "active"} and self.noise != "low"

    @property
    def web_budget(self):
        return (10, 60.0) if self.noise == "low" else ((None, 300.0) if self.profile == "deep" else (30, 120.0))


current_controls = ContextVar("recon_controls", default=ReconControls())
current_cancel = ContextVar("recon_cancel", default=None)


class ReconCancelled(Exception):
    pass


def checkpoint(*, pace=False):
    event = current_cancel.get()
    if event is not None and event.is_set():
        raise ReconCancelled("Reconocimiento cancelado por el usuario.")
    if pace and current_controls.get().noise == "low":
        if event is not None:
            if event.wait(current_controls.get().pace_ms / 1000):
                raise ReconCancelled("Reconocimiento cancelado por el usuario.")
        else:
            time.sleep(current_controls.get().pace_ms / 1000)
