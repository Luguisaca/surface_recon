"""Owned safe characterization and bounded reconnaissance for non-web targets."""
from __future__ import annotations
import hashlib
import ipaddress
from pathlib import Path
import re
import socket
from .model import Target

def _obs(description: str, evidence: dict, *, finding: bool = False, key: str | None = None) -> dict:
    row = {"description": description, "evidence": evidence, "finding": finding, "source": "surface-recon-core"}
    if key:
        row["correlation_key"] = key
    return row

def _printable_strings(data: bytes, limit: int = 30000) -> list[str]:
    return [x.decode("ascii", errors="ignore") for x in re.findall(rb"[ -~]{6,}", data)[:limit]]

def _pe_metadata(data: bytes) -> dict:
    if not data.startswith(b"MZ") or len(data) < 0x40:
        return {}
    offset = int.from_bytes(data[0x3C:0x40], "little")
    if offset + 24 > len(data) or data[offset:offset + 4] != b"PE\x00\x00":
        return {}
    machine = int.from_bytes(data[offset + 4:offset + 6], "little")
    sections = int.from_bytes(data[offset + 6:offset + 8], "little")
    characteristics = int.from_bytes(data[offset + 22:offset + 24], "little")
    return {"machine": hex(machine), "sections": sections, "characteristics": hex(characteristics)}
def recon_artifact(target: Target):
    path = Path(target.value)
    if not path.is_file():
        return [], ()
    data = path.read_bytes()
    head = data[:4096]
    kind = "unknown"
    if head.startswith(b"MZ"): kind = "PE/Windows executable"
    elif head.startswith(b"\x7fELF"): kind = "ELF executable"
    elif head[:2] == b"PK": kind = "ZIP/package container"
    elif head.startswith(b"MSWIM"): kind = "Windows Imaging Format"
    elif head.startswith(b"%PDF"): kind = "PDF document"
    strings = _printable_strings(data)
    refs = []
    for value in strings:
        refs.extend(re.findall(r"https?://[^\s\"'<>]{4,300}", value, flags=re.I))
    refs = list(dict.fromkeys(refs))[:100]
    evidence = {"kind":"artifact","artifact_type":kind,"size":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),"sha1":hashlib.sha1(data).hexdigest(),
        "name":path.name,"pe":_pe_metadata(data)}
    observations = [_obs(f"Artifact characterized: {kind}, {len(data)} bytes", evidence)]
    if refs:
        observations.append(_obs(f"Artifact contains {len(refs)} URL reference(s)",
            {"kind":"artifact-references","urls":refs}))
    covered = ["artifact-identification","binary-identification","metadata-analysis"]
    if kind == "ZIP/package container":
        try:
            import zipfile
            with zipfile.ZipFile(path) as archive:
                entries = archive.infolist()
                total_uncompressed = sum(item.file_size for item in entries)
                suspicious = [item.filename for item in entries
                    if item.filename.startswith(("/", "\\")) or ".." in Path(item.filename).parts]
                observations.append(_obs(f"Archive structure analyzed: {len(entries)} entries",
                    {"kind":"archive-analysis","entries":[item.filename for item in entries[:200]],
                     "entry_count":len(entries),"uncompressed_bytes":total_uncompressed,
                     "unsafe_paths":suspicious[:50]}))
                covered.append("static-analysis")
        except Exception as exc:
            observations.append(_obs("Archive analysis could not be completed",
                {"kind":"decision","reason":"archive-parse-failed","error_type":type(exc).__name__}))
    if kind == "PE/Windows executable":
        try:
            import pefile
            pe = pefile.PE(data=data, fast_load=False)
            imports = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                dll = entry.dll.decode(errors="replace") if entry.dll else "unknown"
                names = [(item.name.decode(errors="replace") if item.name else f"ordinal:{item.ordinal}")
                         for item in entry.imports[:100]]
                imports.append({"library": dll, "symbols": names})
            sections = [{"name": section.Name.rstrip(b"\\x00").decode(errors="replace"),
                         "entropy": round(section.get_entropy(), 3),
                         "size": section.SizeOfRawData} for section in pe.sections]
            dll_chars = int(pe.OPTIONAL_HEADER.DllCharacteristics)
            security = {"aslr": bool(dll_chars & 0x40), "dep_nx": bool(dll_chars & 0x100),
                        "high_entropy_va": bool(dll_chars & 0x20),
                        "signed_directory_present": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)}
            observations.append(_obs("PE static structure analyzed",
                {"kind":"pe-static-analysis","imports":imports,"sections":sections,"mitigations":security}))
            covered.append("static-analysis")
        except Exception as exc:
            observations.append(_obs("PE static analysis could not be completed",
                {"kind":"decision","reason":"pe-parse-failed","error_type":type(exc).__name__}))
    return observations, tuple(covered)
def recon_path(target: Target):
    path = Path(target.value)
    if path.is_file(): return recon_artifact(target)
    if not path.is_dir(): return [], ()
    files = [p for p in path.rglob("*") if p.is_file() and ".git" not in p.parts]
    names = {"package.json","package-lock.json","pyproject.toml","requirements.txt",
        "cargo.toml","cargo.lock","go.mod","pom.xml","build.gradle","dockerfile",
        "docker-compose.yml","compose.yml"}
    manifests = [p for p in files if p.name.lower() in names]
    suffixes = {}
    for p in files:
        suffix = p.suffix.lower() or "[none]"
        suffixes[suffix] = suffixes.get(suffix, 0) + 1
    observations = [_obs(f"Local inventory: {len(files)} file(s), {len(manifests)} manifest(s)",
        {"kind":"inventory","file_count":len(files),
         "manifests":[str(p.relative_to(path)) for p in manifests[:50]],
         "top_extensions":sorted(suffixes.items(), key=lambda x:x[1], reverse=True)[:15]})]
    return observations, ("inventory",)

def recon_host(target: Target):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(target.value, None)})
    except socket.gaierror:
        addresses = []
    observations = [_obs("Host resolution completed",
        {"kind":"host","host":target.value,"addresses":addresses})]
    common = {21:"ftp",22:"ssh",25:"smtp",53:"dns",80:"http",110:"pop3",135:"rpc",
        139:"netbios",143:"imap",443:"https",445:"smb",587:"smtp-submission",993:"imaps",
        995:"pop3s",1433:"mssql",3306:"mysql",3389:"rdp",5432:"postgres",6379:"redis",
        8080:"http-alt",8443:"https-alt"}
    reachable = []
    for port, service in common.items():
        try:
            with socket.create_connection((target.value, port), timeout=0.2):
                reachable.append({"port":port,"service_hint":service})
        except OSError:
            pass
    observations.append(_obs(f"Bounded TCP discovery: {len(reachable)} common port(s) reachable",
        {"kind":"ports","host":target.value,"reachable":reachable,"tested_ports":list(common),
         "scan_scope":"partial-common-ports","tested_port_count":len(common),"full_tcp_range_tested":False}))
    return observations, ("host-discovery","port-discovery-partial")

def recon_network(target: Target):
    network = ipaddress.ip_network(target.value, strict=False)
    observations = [_obs("Network scope characterized",
        {"kind":"network","network":str(network),"version":network.version,
         "address_count":network.num_addresses})]
    if network.num_addresses > 256:
        observations.append(_obs("Active host discovery deferred: network exceeds safe core sweep budget",
            {"kind":"decision","reason":"network-budget","max_active_hosts":256,
             "address_count":network.num_addresses}))
        return observations, ()
    live = []
    ports = (80,443,22,445)
    for address in network.hosts():
        for port in ports:
            try:
                with socket.create_connection((str(address), port), timeout=0.08):
                    live.append({"address":str(address),"evidence_port":port})
                    break
            except OSError:
                pass
    observations.append(_obs(f"Bounded TCP-probe discovery observed {len(live)} host(s) responding on the tested ports",
        {"kind":"network-hosts","hosts":live,"tested_ports":list(ports),
         "scan_scope":"host-discovery-probes","full_tcp_range_tested":False}))
    # The same bounded host evidence also establishes that the tested ports were
    # evaluated for each address; deeper service identification happens in the
    # evidence-driven host pivot.
    return observations, ("host-discovery","port-discovery-partial")

def recon_opaque(target: Target):
    value = target.value.strip()
    features = {
        "length": len(value),
        "contains_uri_scheme": bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)),
        "looks_like_identifier": bool(re.fullmatch(r"[A-Za-z0-9._:@/+\\-]+", value)),
    }
    observations = [_obs("Opaque target preserved and characterized",
        {"kind":"opaque-target","value":value,"features":features})]
    # Autonomous reinterpretation is deliberately conservative: infer only
    # transformations that preserve the submitted target's identity.
    if features["looks_like_identifier"] and "." in value and " " not in value:
        try:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(value, None)})
        except socket.gaierror:
            addresses = []
        if addresses:
            observations.append(_obs("Opaque identifier resolved as a network host",
                {"kind":"decision","reason":"opaque-to-host","host":value,"addresses":addresses}))
            derived = Target(f"{target.id}-host", value, target.scope_state, target_type="host")
            host_obs, host_covered = recon_host(derived)
            observations.extend(host_obs)
            return observations, ("target-characterization","active-reconnaissance",*host_covered)
    observations.append(_obs("Active reconnaissance deferred because no safe interpretation was evidenced",
        {"kind":"decision","reason":"opaque-no-safe-protocol-inference"}))
    return observations, ("target-characterization",)

def static_source_review(target: Target):
    """Bounded owned source review; emits candidates, never auto-confirms vulnerabilities."""
    path = Path(target.value)
    if not path.is_dir():
        return [], ()
    source_suffixes = {".py",".js",".ts",".tsx",".jsx",".java",".go",".rs",".php",".rb",".cs",".ps1"}
    files = [p for p in path.rglob("*") if p.is_file() and ".git" not in p.parts
             and p.suffix.lower() in source_suffixes and p.stat().st_size <= 1_000_000][:500]
    rules = [
        ("dynamic-eval", "eval(", "Dynamic code evaluation"),
        ("tls-verification-disabled", "verify=False", "TLS verification disabled"),
        ("tls-verification-disabled-js", "rejectUnauthorized: false", "TLS verification disabled"),
        ("python-process-exec", "os.system(", "Process execution sink"),
        ("python-subprocess", "subprocess.run(", "Process execution sink"),
    ]
    hits = []
    for source in files:
        try:
            text = source.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rule_id, needle, meaning in rules:
            start = 0
            while len(hits) < 100:
                pos = text.find(needle, start)
                if pos < 0:
                    break
                hits.append({"rule":rule_id,"meaning":meaning,"file":str(source.relative_to(path)),
                             "line":text.count("\n",0,pos)+1})
                start = pos + len(needle)
    return [_obs(f"Owned static review inspected {len(files)} source file(s); {len(hits)} review candidate(s)",
        {"kind":"static-analysis","engine":"surface-recon-core","files_inspected":len(files),
         "candidates":hits,"claim":"review-candidates-not-confirmed-vulnerabilities"})], ("static-analysis",)

def fingerprint_host_services(target: Target, port_observation: dict):
    """Safe bounded protocol handshakes for services already observed as reachable."""
    evidence = port_observation.get("evidence", port_observation)
    reachable = evidence.get("reachable", []) if isinstance(evidence, dict) else []
    results = []
    for item in reachable[:20]:
        port = int(item["port"])
        hint = item.get("service_hint")
        banner = ""
        try:
            with socket.create_connection((target.value, port), timeout=0.5) as sock:
                sock.settimeout(0.5)
                if port in {80, 8080}:
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target.value}\r\n\r\n".encode())
                banner = sock.recv(512).decode("utf-8", errors="replace").strip()
        except OSError:
            pass
        results.append({"port":port,"service_hint":hint,"banner":banner[:300]})
    identified = sum(bool(item.get("banner")) for item in results)
    complete = bool(results) and identified == len(results)
    return [_obs(f"Service fingerprinting obtained protocol evidence for {identified}/{len(results)} reachable service(s)",
        {"kind":"service-fingerprints","host":target.value,"services":results,
         "identified_count":identified,"reachable_count":len(results),"complete":complete})], (
            "service-fingerprinting" if complete else "service-fingerprinting-partial",
        )
