"""Discover reusable assessment tools without installing or assuming them."""

from dataclasses import dataclass
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import xml.etree.ElementTree as ET

from .process import run_process


@dataclass(frozen=True, slots=True)
class ToolCandidate:
    id: str
    capability_id: str
    executable_names: tuple[str, ...]
    purpose: str
    supported_systems: tuple[str, ...]
    license_note: str
    subcapabilities: tuple[str, ...] = ()
    executable: str | None = None
    probe_args: tuple[str, ...] = ()
    identity_markers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EnvironmentProvider:
    executable: str
    name: str
    evidence: tuple[str, ...]
    inferred_subcapabilities: tuple[str, ...]
    executable_adapter_available: bool = False


_CAPABILITY_VOCABULARY = {
    "host-discovery": ("network discovery", "host discovery", "network exploration", "network scanner", "network mapper"),
    "port-discovery": ("port scan", "port scanner", "network exploration", "network scanner", "network mapper"),
    "service-fingerprinting": ("service detection", "version detection", "service fingerprint", "network exploration", "network mapper"),
    "http-probing": ("http probe", "http toolkit", "web server", "web scanner"),
    "content-discovery": ("content discovery", "web fuzzer", "directory discovery", "discovery tool for directories", "web scanner"),
    "technology-fingerprinting": ("technology detection", "web fingerprint", "web scanner"),
    "template-detection": ("template scanner", "vulnerability scanner", "web scanner"),
    "injection-testing": ("sql injection", "injection scanner", "database takeover tool"),
    "client-side-injection-testing": ("cross site scripting", "xss scanner", "web fuzzer"),
    "access-control-testing": ("authorization testing", "access control testing", "web fuzzer"),
    "secret-detection": ("secret scanner", "secret detection"),
    "dependency-analysis": ("dependency scanner", "vulnerability scanner", "package scanner"),
    "static-analysis": ("static analysis", "static analyzer", "source code analysis", "source code scanner"),
}


def infer_subcapabilities(*evidence: str) -> tuple[str, ...]:
    text = " ".join(evidence).lower()
    return tuple(sorted(cap for cap, terms in _CAPABILITY_VOCABULARY.items() if any(term in text for term in terms)))


def inventory_environment_providers(metadata: dict[str, str] | None = None) -> list[EnvironmentProvider]:
    """Inventory PATH without executing discovered programs; metadata may come from OS package records."""
    metadata = metadata or {}
    known_adapters = {c.id for c in _CANDIDATES}
    rows, seen = [], set()
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        root = Path(raw.strip('"')) if raw else None
        if not root or not root.is_dir():
            continue
        try: entries = root.iterdir()
        except OSError: continue
        for path in entries:
            if not path.is_file(): continue
            name = path.stem.lower() if platform.system() == "Windows" else path.name.lower()
            if name in seen: continue
            seen.add(name)
            description = metadata.get(name, "")
            inferred = infer_subcapabilities(name, description)
            if inferred:
                rows.append(EnvironmentProvider(str(path), name, tuple(x for x in (description,) if x), inferred, name in known_adapters))
    return rows


def discover_linux_package_providers() -> list[EnvironmentProvider]:
    """Infer capabilities from installed-package descriptions, then resolve their PATH executables."""
    if platform.system() != "Linux":
        return []
    dpkg = shutil.which("dpkg-query")
    if not dpkg:
        return []
    catalog = run_process((dpkg, "-W", "-f=${binary:Package}\t${Description}\n"), timeout=20, action_kind="metadata")
    if not catalog.succeeded:
        return []
    providers, seen = [], set()
    for line in catalog.stdout.splitlines():
        if "\t" not in line:
            continue
        package, description = line.split("\t", 1)
        inferred = infer_subcapabilities(description)
        if not inferred:
            continue
        listing = run_process((dpkg, "-L", package), timeout=5, action_kind="metadata")
        if not listing.succeeded:
            continue
        for raw in listing.stdout.splitlines():
            path = Path(raw)
            if not path.name or not path.is_file():
                continue
            # Package-level descriptions apply safely only to the package's
            # primary same-name executable; helper binaries need their own evidence.
            if path.name.lower() != package.split(":", 1)[0].lower():
                continue
            resolved = shutil.which(path.name)
            if not resolved or Path(resolved).resolve() != path.resolve():
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            providers.append(EnvironmentProvider(key, path.name.lower(), (f"package:{package}", description), inferred, path.name.lower() in {c.id for c in _CANDIDATES}))
    return providers


@lru_cache(maxsize=1)
def discover_environment_providers() -> tuple[EnvironmentProvider, ...]:
    """Merge generic PATH and OS-package discovery into one deduplicated provider inventory."""
    rows = [*inventory_environment_providers(), *discover_linux_package_providers()]
    merged: dict[str, EnvironmentProvider] = {}
    for row in rows:
        key = str(Path(row.executable).resolve())
        previous = merged.get(key)
        if previous is None:
            merged[key] = row
            continue
        merged[key] = EnvironmentProvider(
            row.executable, row.name,
            tuple(dict.fromkeys((*previous.evidence, *row.evidence))),
            tuple(sorted(set(previous.inferred_subcapabilities) | set(row.inferred_subcapabilities))),
            previous.executable_adapter_available or row.executable_adapter_available,
        )
    return tuple(sorted(merged.values(), key=lambda item: (item.name, item.executable)))


def providers_for(required_subcapabilities) -> list[EnvironmentProvider]:
    required = set(required_subcapabilities)
    return [row for row in discover_environment_providers() if required.intersection(row.inferred_subcapabilities)]


def evidence_required_subcapabilities(observations) -> tuple[str, ...]:
    """Derive validation needs only from security hypotheses actually observed."""
    required: set[str] = set()
    for observation in observations:
        evidence = observation.get("evidence") if isinstance(observation, dict) else None
        if not isinstance(evidence, dict) or evidence.get("kind") != "security-hypothesis":
            continue
        hypothesis = evidence.get("hypothesis")
        if hypothesis in {"input-validation", "form-input-validation"}:
            required.update({"injection-testing", "client-side-injection-testing"})
        elif hypothesis == "authorization-boundary":
            required.add("access-control-testing")
    return tuple(sorted(required))


def select_tools_for_gaps(capability_id: str, missing_subcapabilities) -> list[ToolCandidate]:
    """Select the smallest verified adapter set that adds currently missing coverage."""
    remaining = set(missing_subcapabilities)
    selected: list[ToolCandidate] = []
    candidates = discover_tools(capability_id)
    while remaining:
        ranked = [
            (len(remaining.intersection(tool.subcapabilities)), tool)
            for tool in candidates if tool not in selected
        ]
        ranked = [item for item in ranked if item[0] > 0]
        if not ranked:
            break
        _, best = max(ranked, key=lambda item: (item[0], item[1].id))
        selected.append(best)
        remaining.difference_update(best.subcapabilities)
    return selected


@dataclass(frozen=True, slots=True)
class ToolRecommendation:
    tool_id: str
    capability_id: str
    purpose: str
    compatibility: str
    license_note: str
    install_automatically: bool = False


_CANDIDATES = (
    ToolCandidate(
        "httpx",
        "http-recon",
        ("httpx",),
        "HTTP probing and metadata collection.",
        ("Linux", "Windows", "Darwin"),
        "MIT; verify the actual installed/distributed version before relying on this metadata.",
        ("http-probing", "technology-fingerprinting"),
        probe_args=("-version",),
        identity_markers=("projectdiscovery",),
    ),
    ToolCandidate(
        "nuclei",
        "http-recon",
        ("nuclei",),
        "Template-based detection for applicable web/network conditions.",
        ("Linux", "Windows", "Darwin"),
        "MIT; templates and their behavior must be evaluated separately.",
        ("template-detection",),
    ),
    ToolCandidate(
        "git",
        "repository-recon",
        ("git",),
        "Repository inventory and metadata inspection.",
        ("Linux", "Windows", "Darwin"),
        "GPL-2.0; use as an external process and review distribution obligations if packaging changes.",
        ("inventory",),
    ),
    ToolCandidate(
        "trivy",
        "repository-recon",
        ("trivy",),
        "Repository secret detection using Trivy's local secret scanner.",
        ("Linux", "Windows", "Darwin"),
        "Apache-2.0; external process. Vulnerability databases are not downloaded by this adapter.",
        ("secret-detection", "dependency-analysis"),
    ),
    ToolCandidate(
        "trivy",
        "directory-recon",
        ("trivy",),
        "Filesystem secret detection using Trivy's local secret scanner.",
        ("Linux", "Windows", "Darwin"),
        "Apache-2.0; external process. Vulnerability databases are not downloaded by this adapter.",
        ("secret-detection", "dependency-analysis"),
    ),
    ToolCandidate(
        "nmap",
        "host-recon",
        ("nmap",),
        "Host, port, service and version discovery.",
        ("Linux", "Windows", "Darwin"),
        "NPSL; review licensing before redistribution or embedding.",
        ("host-discovery", "port-discovery", "service-fingerprinting"),
    ),
)


def candidates_for(capability_id: str) -> list[ToolCandidate]:
    return [candidate for candidate in _CANDIDATES if candidate.capability_id == capability_id]


def _discovery_roots() -> list[Path]:
    """Return bounded local tool roots without modifying PATH or installing anything."""
    roots: list[Path] = []
    configured = os.environ.get("SURFACE_RECON_TOOL_PATHS", "")
    for raw in configured.split(os.pathsep):
        if raw.strip():
            roots.append(Path(raw).expanduser())

    cwd = Path.cwd().resolve()
    for ancestor in (cwd, *cwd.parents):
        roots.extend((ancestor / "Tools", ancestor / "tools"))

    unique: list[Path] = []
    for root in roots:
        if root not in unique and root.is_dir():
            unique.append(root)
    return unique


def _find_executable(names: tuple[str, ...]) -> str | None:
    for name in names:
        if path := shutil.which(name):
            return path

    wanted = {name.lower() for name in names}
    if platform.system() == "Windows":
        wanted |= {f"{name}.exe".lower() for name in names}

    for root in _discovery_roots():
        for path in root.glob("*/*/*"):
            if path.is_file() and path.name.lower() in wanted:
                return str(path)
        for path in root.glob("*/*"):
            if path.is_file() and path.name.lower() in wanted:
                return str(path)
        for path in root.iterdir():
            if path.is_file() and path.name.lower() in wanted:
                return str(path)
    return None


def _provider_identity_matches(candidate: ToolCandidate, executable: str) -> bool:
    """Verify an adapter's declared CLI identity when its contract requires a probe."""
    if not candidate.probe_args or not candidate.identity_markers:
        return True
    probe = run_process((executable, *candidate.probe_args), timeout=5, action_kind="metadata")
    text = f"{probe.stdout}\n{probe.stderr}".lower()
    return probe.succeeded and all(marker.lower() in text for marker in candidate.identity_markers)


def discover_tools(capability_id: str) -> list[ToolCandidate]:
    discovered = []
    for candidate in candidates_for(capability_id):
        executable = _find_executable(candidate.executable_names)
        if executable and _provider_identity_matches(candidate, executable):
            discovered.append(
                ToolCandidate(
                    candidate.id,
                    candidate.capability_id,
                    candidate.executable_names,
                    candidate.purpose,
                    candidate.supported_systems,
                    candidate.license_note,
                    candidate.subcapabilities,
                    executable,
                )
            )
    return discovered


def recommendations_for(
    capability_id: str,
    required_subcapabilities=None,
) -> list[ToolRecommendation]:
    system = platform.system() or "Unknown"
    available_ids = {tool.id for tool in discover_tools(capability_id)}
    required = set(required_subcapabilities or ())
    recommendations = []
    for candidate in candidates_for(capability_id):
        if candidate.id in available_ids:
            continue
        if required and not required.intersection(candidate.subcapabilities):
            continue
        compatible = system in candidate.supported_systems
        recommendations.append(
            ToolRecommendation(
                tool_id=candidate.id,
                capability_id=capability_id,
                purpose=candidate.purpose,
                compatibility=(
                    f"Candidate supports {system}." if compatible
                    else f"Compatibility with {system} is not established by this catalog."
                ),
                license_note=candidate.license_note,
            )
        )
    return recommendations


@dataclass(frozen=True, slots=True)
class ToolExecution:
    tool_id: str
    succeeded: bool
    observations: list[dict]
    error: str | None = None
    covered_subcapabilities: tuple[str, ...] = ()


def _parse_nmap_hosts(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") not in {None, "up"}:
            continue
        address_rows = [
            x for x in host.findall("address")
            if x.get("addr") and x.get("addrtype") in {None, "ipv4", "ipv6"}
        ]
        addresses = [x.get("addr") for x in address_rows]
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            services.append({
                "protocol": port.get("protocol"), "port": int(port.get("portid") or 0),
                "service": svc.get("name") if svc is not None else None,
                "tunnel": svc.get("tunnel") if svc is not None else None,
                "method": svc.get("method") if svc is not None else None,
                "confidence": int(svc.get("conf")) if svc is not None and (svc.get("conf") or "").isdigit() else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })
        hosts.append({"addresses": addresses, "services": services})
    return hosts


def execute_tool(tool: ToolCandidate, target) -> ToolExecution:
    """Execute a discovered tool using bounded, non-destructive defaults."""
    if not tool.executable:
        return ToolExecution(tool.id, False, [], "Tool executable is unavailable.")

    if tool.id == "nmap" and target.target_type == "network":
        discovery_args = (tool.executable, "-sn", "-T3", "-oX", "-", target.value)
        discovery = run_process(
            discovery_args, timeout=300.0, target=target, action_kind="recon"
        )
        if not discovery.succeeded:
            return ToolExecution(tool.id, False, [], discovery.stderr or "Nmap host discovery failed.")
        try:
            discovered_hosts = _parse_nmap_hosts(discovery.stdout)
        except ET.ParseError:
            return ToolExecution(tool.id, False, [], "Nmap host discovery returned invalid XML.")
        live = [address for host in discovered_hosts for address in host["addresses"][:1]]
        observations = [{
            "description": f"Nmap host discovery observed {len(live)} live host(s)",
            "evidence": {
                "kind": "nmap-host-discovery", "network": target.value,
                "hosts": live, "command": list(discovery_args),
            },
            "finding": False, "source": tool.id,
        }]
        if not live:
            return ToolExecution(
                tool.id, True, observations,
                covered_subcapabilities=("host-discovery",),
            )
        try:
            network = ipaddress.ip_network(target.value, strict=False)
        except ValueError:
            network = None
        if (
            network is not None and network.version == 4 and network.prefixlen <= 30
            and str(network.network_address) in live and str(network.broadcast_address) in live
        ):
            observations.append({
                "description": "Nmap host discovery was non-discriminating; full TCP deepening was not started",
                "evidence": {
                    "kind": "decision", "reason": "provider-host-discovery-nondiscriminating",
                    "network": target.value, "hosts_reported_live": len(live),
                },
                "finding": False, "source": tool.id,
            })
            return ToolExecution(
                tool.id, True, observations,
                covered_subcapabilities=("host-discovery",),
            )
        deep_args = (
            # Keep hosts with zero open ports in XML so a completed full-range scan
            # is not mistaken for a host that was never deepened.
            tool.executable, "-Pn", "-p-", "-sV", "--version-light",
            "-T3", "-oX", "-", *live,
        )
        deep = run_process(deep_args, timeout=900.0, target=target, action_kind="recon")
        if not deep.succeeded:
            observations.append({
                "description": "Nmap per-host deepening did not complete",
                "evidence": {"kind": "decision", "reason": "provider-deepening-failed"},
                "finding": False, "source": tool.id,
            })
            return ToolExecution(
                tool.id, True, observations, deep.stderr,
                covered_subcapabilities=("host-discovery",),
            )
        try:
            hosts = _parse_nmap_hosts(deep.stdout)
        except ET.ParseError:
            return ToolExecution(
                tool.id, True, observations, "Nmap deepening returned invalid XML.",
                covered_subcapabilities=("host-discovery",),
            )
        deep_addresses = {
            address for host in hosts for address in host.get("addresses", [])
        }
        missing_deep = sorted(set(live) - deep_addresses)
        complete = not missing_deep
        observations.append({
            "description": f"Nmap deepened {len(deep_addresses)} of {len(live)} discovered host(s) across TCP 1-65535",
            "evidence": {
                "kind": "nmap-surface", "hosts": hosts,
                "full_tcp_range_tested": complete, "scan_scope": "tcp-1-65535",
                "hosts_requested": live, "hosts_missing_from_deepening": missing_deep,
                "discovery_command": list(discovery_args), "command": list(deep_args),
            },
            "finding": False, "source": tool.id,
        })
        covered = (
            ("host-discovery", "port-discovery", "service-fingerprinting")
            if complete else ("host-discovery", "port-discovery-partial")
        )
        return ToolExecution(
            tool.id, True, observations,
            covered_subcapabilities=covered,
        )

    if tool.id == "httpx":
        args = (tool.executable, "-u", target.value, "-json", "-silent", "-no-stdin", "-duc")
    elif tool.id == "git":
        args = (tool.executable, "-C", target.value, "ls-files")
    elif tool.id == "trivy":
        args = (
            tool.executable, "fs",
            "--scanners", "vuln,secret",
            "--skip-db-update",
            "--format", "json",
            "--quiet",
            "--skip-dirs", ".git",
            target.value,
        )
    elif tool.id == "nmap":
        # Existing host-recon provider. A single host receives complete TCP
        # coverage; network scopes use a bounded first phase and must remain
        # explicitly partial until evidence justifies per-host deepening.
        if target.target_type == "host":
            args = (tool.executable, "-Pn", "-p-", "--open", "-sV", "--version-light", "-T3", "-oX", "-", target.value)
        else:
            args = (tool.executable, "-Pn", "--top-ports", "1000", "--open", "-sV", "--version-light", "-T3", "-oX", "-", target.value)
    elif tool.id == "nuclei":
        configured_templates = os.environ.get("SURFACE_RECON_NUCLEI_TEMPLATES")
        template_candidates = [
            Path(configured_templates).expanduser() if configured_templates else None,
            Path.home() / "nuclei-templates",
        ]
        template_root = next((p for p in template_candidates if p is not None and p.exists()), None)
        if template_root is None:
            return ToolExecution(
                tool.id, False, [],
                "Nuclei templates are unavailable; no templates were downloaded automatically.",
            )
        # Evidence-driven subset: never launch the complete template corpus.
        # Match observed technology evidence to HTTP template filenames and cap the set.
        tokens = []
        # Template selection is technology-driven. Route/resource names such as
        # "admin", "user", or "security" are too generic and previously selected
        # unrelated product templates by filename coincidence.
        for signal in getattr(target, "technology_hints", []):
            value = str(signal).split(":", 1)[-1].strip().lower()
            for token in re.findall(r"[a-z0-9][a-z0-9._-]{2,40}", value):
                token = token.split("/", 1)[0].strip("._-")
                if len(token) >= 3 and token not in {"server", "powered", "via"}:
                    tokens.append(token)
        matched_templates = [template_root] if template_root.is_file() else []
        search_root = template_root
        if template_root.is_dir() and (template_root / "http").is_dir():
            search_root = template_root / "http"
        for token in sorted(dict.fromkeys(tokens), key=lambda value: (len(value), value)):
            if template_root.is_file():
                break
            unsafe_path_markers = ("token-spray", "brute", "fuzz", "dos", "headless", "default-login", "dast")
            token_pattern = re.compile(
                rf"(?<![a-z0-9]){re.escape(token.replace('_', '-'))}(?![a-z0-9])"
            )
            candidates = [
                p for p in search_root.rglob(f"*{token}*.yaml")
                if token_pattern.search(p.stem.lower().replace("_", "-"))
                and not any(marker in str(p).lower() for marker in unsafe_path_markers)
            ]
            candidates.sort(key=lambda p: (
                0 if "exposures\\configs" in str(p).lower() or "exposures/configs" in str(p).lower() else
                1 if "misconfiguration" in str(p).lower() else 2,
                len(p.name), p.name,
            ))
            for candidate in candidates[:8]:
                if candidate not in matched_templates:
                    matched_templates.append(candidate)
                if len(matched_templates) >= 24:
                    break
            if len(matched_templates) >= 24:
                break
        if not matched_templates:
            return ToolExecution(tool.id, False, [],
                "No evidence-matched safe Nuclei template subset was selected.")
        template_args = tuple(arg for path in matched_templates for arg in ("-t", str(path)))
        # Exclude categories that can be intrusive or availability-impacting.
        args = (
            tool.executable, "-u", target.value, *template_args,
            "-jsonl", "-silent", "-no-stdin", "-duc",
            "-etags", "intrusive,dos,fuzz,bruteforce",
            "-rl", "5",
            "-c", "2",
            "-bs", "2",
            "-timeout", "5",
            "-retries", "0",
        )
    else:
        return ToolExecution(tool.id, False, [], "No safe execution adapter is defined.")

    result = run_process(args, timeout=300.0 if tool.id == "nmap" else 60.0, target=target, action_kind="recon")
    if not result.succeeded:
        return ToolExecution(tool.id, False, [], result.stderr or f"exit code {result.returncode}")

    provenance = {
        "description": f"Executed {tool.id}: {tool.purpose}",
        "evidence": {"kind": "execution", "tool": tool.id, "command": list(args), "purpose": tool.purpose},
        "finding": False,
        "source": tool.id,
    }

    if tool.id == "nmap":
        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError:
            return ToolExecution(tool.id, False, [], "Nmap returned invalid XML.")
        hosts = []
        for host in root.findall("host"):
            address_rows = [
                x for x in host.findall("address")
                if x.get("addr") and x.get("addrtype") in {None, "ipv4", "ipv6"}
            ]
            addresses = [x.get("addr") for x in address_rows]
            services = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                services.append({
                    "protocol": port.get("protocol"), "port": int(port.get("portid") or 0),
                    "service": svc.get("name") if svc is not None else None,
                    "tunnel": svc.get("tunnel") if svc is not None else None,
                    "method": svc.get("method") if svc is not None else None,
                    "confidence": int(svc.get("conf")) if svc is not None and (svc.get("conf") or "").isdigit() else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                })
            hosts.append({"addresses":addresses,"services":services})
        full = target.target_type == "host"
        covered = ("host-discovery","port-discovery","service-fingerprinting") if full else (
            "host-discovery","port-discovery-partial","service-fingerprinting")
        return ToolExecution(tool.id, True, [{
            "description": f"Nmap observed {sum(len(x['services']) for x in hosts)} open TCP port(s) and attempted service/version fingerprinting",
            "evidence": {"kind":"nmap-surface","hosts":hosts,"full_tcp_range_tested":full,
                         "scan_scope":"tcp-1-65535" if full else "top-1000-tcp"},
            "finding": False, "source": tool.id,
        }, provenance], covered_subcapabilities=covered)

    if tool.id == "git":
        files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return ToolExecution(
            tool.id,
            True,
            [{
                "description": f"Repository inventory: {len(files)} tracked files",
                "evidence": {"tracked_file_count": len(files), "sample": files[:10]},
                "finding": False,
                "source": tool.id,
            }, provenance],
            covered_subcapabilities=tool.subcapabilities,
        )

    if tool.id == "trivy":
        try:
            report = json.loads(result.stdout.lstrip("\ufeff"))
        except json.JSONDecodeError:
            return ToolExecution(tool.id, False, [], "Trivy returned invalid JSON.")
        observations = []
        package_count = 0
        for scan_result in report.get("Results") or []:
            target_name = scan_result.get("Target") or target.value
            package_count += len(scan_result.get("Packages") or [])
            for vulnerability in scan_result.get("Vulnerabilities") or []:
                vuln_id = vulnerability.get("VulnerabilityID") or "vulnerability"
                pkg = vulnerability.get("PkgName") or "package"
                observations.append({
                    "description": f"Trivy vulnerability: {vuln_id} in {pkg}",
                    "evidence": {
                        "vulnerability_id": vuln_id,
                        "package": pkg,
                        "installed_version": vulnerability.get("InstalledVersion"),
                        "fixed_version": vulnerability.get("FixedVersion"),
                        "severity": vulnerability.get("Severity"),
                        "target": target_name,
                    },
                    "finding": True,
                    "source": tool.id,
                    "correlation_key": f"vuln:{vuln_id}:{pkg}:{target_name}",
                })
            for secret in scan_result.get("Secrets") or []:
                rule_id = secret.get("RuleID") or "secret"
                title = secret.get("Title") or rule_id
                observations.append({
                    "description": f"Trivy secret: {title}",
                    "evidence": {
                        "rule_id": rule_id,
                        "target": target_name,
                        "start_line": secret.get("StartLine"),
                        "severity": secret.get("Severity"),
                    },
                    "finding": True,
                    "source": tool.id,
                    "correlation_key": f"secret:{rule_id}:{target_name}:{secret.get('StartLine')}",
                })
        if not observations:
            observations.append({
                "description": "Trivy dependency/secret scan completed: no findings reported",
                "evidence": {
                    "target": target.value,
                    "scanners": ["vuln", "secret"],
                    "packages_analyzed": package_count,
                },
                "finding": False,
                "source": tool.id,
            })
        observations.append(provenance)
        return ToolExecution(
            tool.id, True, observations,
            covered_subcapabilities=tool.subcapabilities,
        )

    observations = []
    covered_subcapabilities = set(tool.subcapabilities)
    for raw_line in result.stdout.splitlines():
        if not raw_line.strip():
            continue
        try:
            item = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        if tool.id == "httpx":
            description = f"HTTP {item.get('status_code', 'unknown')}: {item.get('url', target.value)}"
            evidence = {
                "url": item.get("url", target.value),
                "status_code": item.get("status_code"),
                "page_title": item.get("title"),
                "server_header": item.get("webserver"),
                "tech": item.get("tech"),
            }
        else:
            info = item.get("info") or {}
            description = f"Nuclei: {info.get('name') or item.get('template-id') or 'observed condition'}"
            evidence = {
                "template_id": item.get("template-id"),
                "severity": info.get("severity"),
                "matched_at": item.get("matched-at"),
            }
            extracted = item.get("extracted-results") or item.get("extracted_results")
            if extracted:
                evidence["extracted_results"] = extracted
                covered_subcapabilities.add("content-discovery")
        severity = evidence.get("severity") if tool.id == "nuclei" else None
        observation = {
            "description": description,
            "evidence": evidence,
            "finding": tool.id == "nuclei" and severity not in {None, "info", "unknown"},
            "source": tool.id,
        }
        if tool.id == "nuclei":
            observation["correlation_key"] = (
                f"template:{evidence.get('template_id')}:{evidence.get('matched_at')}"
            )
        observations.append(observation)

    observations.append(provenance)
    return ToolExecution(tool.id, True, observations, covered_subcapabilities=tuple(sorted(covered_subcapabilities)))
