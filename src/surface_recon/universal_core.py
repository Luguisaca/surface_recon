"""Owned safe characterization and bounded reconnaissance for non-web targets."""
from __future__ import annotations
import hashlib
import ipaddress
from pathlib import Path
import re
import socket
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
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
    elif path.suffix.lower() in {".md", ".markdown"} and b"\x00" not in data:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            kind = "Markdown document"
    strings = _printable_strings(data)
    refs = []
    for value in strings:
        refs.extend(re.findall(r"https?://[^\s\"'<>]{4,300}", value, flags=re.I))
    refs = list(dict.fromkeys(refs))[:100]
    evidence = {"kind":"artifact","artifact_type":kind,"size":len(data),
        "sha256":hashlib.sha256(data).hexdigest(),
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
_NON_FIRST_PART_DIRS = {".git", ".venv", "venv", "node_modules", "build", "dist", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}

def _is_first_party_path(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    return not any(part.lower() in _NON_FIRST_PART_DIRS for part in relative.parts[:-1])

def _inventory_tree(path):
    import os
    all_files = []
    subdirectories = []
    skipped_directories = []
    errors = []
    for directory, dirs, names in os.walk(path, followlinks=False, onerror=lambda exc: errors.append(type(exc).__name__)):
        from .controls import checkpoint
        checkpoint()
        root = Path(directory)
        for name in list(dirs):
            child = root / name
            if child.is_symlink() or child.is_junction():
                dirs.remove(name)
                skipped_directories.append(str(child.relative_to(path)))
            elif name.lower() in _NON_FIRST_PART_DIRS:
                # Enumerate metadata to preserve the excluded-file count; never
                # read these files for first-party analysis.
                skipped_directories.append(str(child.relative_to(path)))
            elif _is_first_party_path(child / "placeholder", path):
                subdirectories.append(str(child.relative_to(path)))
        all_files.extend(root / name for name in names if (root / name).is_file() and not (root / name).is_symlink())
    return all_files, subdirectories, skipped_directories, errors


def recon_path(target: Target):
    path = Path(target.value)
    if path.is_file(): return recon_artifact(target)
    if not path.is_dir(): return [], ()
    all_files, subdirectories, skipped_directories, errors = _inventory_tree(path)
    files = [p for p in all_files if _is_first_party_path(p, path)]
    excluded_files = len(all_files) - len(files)
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
         "recursive": True, "visited_subdirectories": subdirectories,
         "skipped_subdirectories": skipped_directories, "read_errors": errors,
         "frontier_exhausted": not errors,
         "zero_files_reason": ("No se leyeron archivos propios; revisa los subdirectorios omitidos y errores de lectura." if errors or skipped_directories else "El árbol recorrido no contiene archivos propios regulares.") if not files else None,
         "manifests":[str(p.relative_to(path)) for p in manifests[:50]],
         "top_extensions":sorted(suffixes.items(), key=lambda x:x[1], reverse=True)[:15],
         "excluded_non_first_party_files":excluded_files,
         "source_boundary_policy":"generated/dependency/environment trees excluded from first-party inventory"})]
    return observations, ("inventory-partial",) if errors else ("inventory",)

def recon_host(target: Target):
    from .controls import checkpoint
    checkpoint()
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
        checkpoint(pace=True)
        try:
            with socket.create_connection((target.value, port), timeout=0.2):
                reachable.append({"port":port,"service_hint":service})
        except OSError:
            pass
    observations.append(_obs(f"Bounded TCP discovery: {len(reachable)} common port(s) reachable",
        {"kind":"ports","host":target.value,"reachable":reachable,"tested_ports":list(common),
         "scan_scope":"partial-common-ports","tested_port_count":len(common),"full_tcp_range_tested":False}))
    return observations, ("host-discovery","port-discovery-partial")

def _usable_neighbor_rows(network, rows):
    """Keep only credible, in-scope neighbor evidence; never infer device identity."""
    usable = []
    for row in rows:
        address = str(row.get("address") or "")
        mac = str(row.get("mac") or "").lower()
        state = str(row.get("state") or "")
        try:
            in_scope = ipaddress.ip_address(address) in network
        except ValueError:
            in_scope = False
        if not in_scope or state.lower() == "unreachable":
            continue
        if address in {str(network.network_address), str(network.broadcast_address)}:
            continue
        if mac in {"", "00-00-00-00-00-00", "00:00:00:00:00:00", "ff-ff-ff-ff-ff-ff", "ff:ff:ff:ff:ff:ff"}:
            continue
        usable.append({"address": address, "mac": mac, "state": state})
    return usable


def _local_neighbor_evidence(network):
    """Best-effort local neighbor cache. No packets are sent and failure is non-fatal."""
    import subprocess
    import sys
    if sys.platform != "win32":
        return []
    try:
        completed = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=2, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in completed.stdout.splitlines():
        match = re.search(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})\s+(\S+)", line)
        if match:
            rows.append({"address": match.group(1), "mac": match.group(2), "state": "observed"})
    return _usable_neighbor_rows(network, rows)



def _parse_ssdp_response(payload: bytes, peer: str, network) -> dict | None:
    """Parse identity hints explicitly announced by an in-scope SSDP responder."""
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return None
    if address not in network:
        return None
    text = payload.decode("utf-8", errors="replace")
    headers = {}
    for line in text.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    if not headers:
        return None
    return {
        "address": peer,
        "server": headers.get("server"),
        "location": headers.get("location"),
        "usn": headers.get("usn"),
        "st": headers.get("st"),
        "provenance": "ssdp-announcement-response",
        "identity_inferred": False,
    }


def _local_ipv4_addresses(network) -> list[str]:
    """Return local IPv4 addresses inside the submitted network without probing peers."""
    addresses = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = item[4][0]
            if ipaddress.ip_address(address) in network:
                addresses.add(address)
    except (OSError, socket.gaierror):
        pass
    return sorted(addresses)


def _discover_ssdp(network, *, timeout: float = 1.5) -> list[dict]:
    """Bounded standards-based SSDP discovery per local in-scope interface."""
    if network.version != 4:
        return []
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    rows = {}
    interfaces = _local_ipv4_addresses(network) or [None]
    for local_address in interfaces:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.settimeout(timeout)
            if local_address:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
            sock.sendto(message, ("239.255.255.250", 1900))
            while True:
                try:
                    payload, peer = sock.recvfrom(65535)
                except socket.timeout:
                    break
                row = _parse_ssdp_response(payload, peer[0], network)
                if row:
                    row["local_interface"] = local_address
                    rows[(row["address"], row.get("usn"), row.get("st"))] = row
        except OSError:
            continue
        finally:
            sock.close()
    return list(rows.values())


def _parse_ws_discovery_response(payload: bytes, peer: str, network) -> list[dict]:
    """Extract WS-Discovery ProbeMatch hints without authenticating to a device."""
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return []
    if address not in network:
        return []
    try:
        root = ET.fromstring(payload)
    except ET.ParseError:
        return []
    rows = []
    for match in root.iter():
        if not match.tag.endswith("ProbeMatch"):
            continue
        values = {"address": peer, "types": [], "scopes": [], "xaddrs": []}
        for node in match.iter():
            value = (node.text or "").strip()
            if node.tag.endswith("Address") and value:
                values["endpoint"] = value
            elif node.tag.endswith("Types") and value:
                values["types"].extend(value.split())
            elif node.tag.endswith("Scopes") and value:
                values["scopes"].extend(value.split())
            elif node.tag.endswith("XAddrs") and value:
                values["xaddrs"].extend(value.split())
        values.update({
            "provenance": "ws-discovery-probe-match",
            "identity_inferred": False,
        })
        rows.append(values)
    return rows


def _discover_ws(network, *, timeout: float = 1.5, rounds: int = 3) -> list[dict]:
    """Bounded repeated WS-Discovery Probes; union intermittent responses without identity claims."""
    if network.version != 4:
        return []
    rounds = max(1, min(rounds, 3))
    rows = {}
    for round_number in range(1, rounds + 1):
        message_id = f"urn:uuid:{uuid.uuid4()}"
        payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <e:Header>
  <w:MessageID>{message_id}</w:MessageID>
  <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body><d:Probe /></e:Body>
</e:Envelope>""".encode("utf-8")
        for local_address in (_local_ipv4_addresses(network) or [None]):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                sock.settimeout(timeout)
                if local_address:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_address))
                sock.sendto(payload, ("239.255.255.250", 3702))
                while True:
                    try:
                        response, peer = sock.recvfrom(65535)
                    except socket.timeout:
                        break
                    for row in _parse_ws_discovery_response(response, peer[0], network):
                        key = (row["address"], row.get("endpoint"), tuple(row["types"]), tuple(row["xaddrs"]))
                        previous = rows.get(key)
                        if previous is None:
                            row["observed_rounds"] = [round_number]
                            row["rounds_attempted"] = rounds
                            rows[key] = row
                        elif round_number not in previous["observed_rounds"]:
                            previous["observed_rounds"].append(round_number)
            except OSError:
                continue
            finally:
                sock.close()
    return list(rows.values())



def _parse_windows_video_devices(output: str) -> list[dict]:
    """Normalize Windows PnP rows without opening capture devices."""
    rows, seen = [], set()
    for line in output.splitlines():
        parts = line.split("\t", 3)
        if len(parts) != 4:
            continue
        device_class, name, instance_id, status = (part.strip() for part in parts)
        if not name or not instance_id:
            continue
        lower = name.lower()
        camera = device_class.lower() == "camera"
        media_video = device_class.lower() == "media" and any(token in lower for token in ("camera", "webcam", "droidcam video", "insta360"))
        if not (camera or media_video):
            continue
        key = (device_class.lower(), lower, instance_id.lower())
        if key in seen:
            continue
        seen.add(key)
        match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", instance_id, re.I)
        hardware_key = f"usb:{match.group(1).lower()}:{match.group(2).lower()}" if match else f"instance:{instance_id.lower()}"
        virtual = instance_id.upper().startswith(("ROOT\\", "SWD\\"))
        rows.append({"name": name, "device_class": device_class, "instance_id": instance_id, "status": status,
            "source_class": "virtual-video-source" if virtual else "local-video-source",
            "transport": "virtual" if virtual else ("usb" if instance_id.upper().startswith("USB\\") else "local"),
            "hardware_key": hardware_key, "provenance": "windows-pnp-inventory", "capture_opened": False})
    return rows


def _group_local_video_sources(interfaces: list[dict]) -> list[dict]:
    """Group multiple OS interfaces belonging to the same logical capture source."""
    groups = {}
    for item in interfaces:
        key = item["hardware_key"]
        group = groups.setdefault(key, {
            "source_id": key,
            "names": [],
            "source_class": item["source_class"],
            "transport": item["transport"],
            "status": "DISCOVERED",
            "provenance": item["provenance"],
            "capture_validated": False,
            "interfaces": [],
        })
        if item["name"] not in group["names"]:
            group["names"].append(item["name"])
        group["interfaces"].append({
            "device_class": item["device_class"],
            "instance_id": item["instance_id"],
            "status": item["status"],
        })
    return list(groups.values())


def discover_local_video_sources() -> tuple[list[dict], dict | None]:
    """Inventory OS-announced video sources without activating or reading a camera."""
    if sys.platform != "win32":
        return [], {"reason": "local-video-inventory-not-implemented-for-platform", "platform": sys.platform, "absence_claim": False}
    script = "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.Class -in @('Camera','MEDIA') } | ForEach-Object { [string]::Join([char]9, @($_.Class,$_.FriendlyName,$_.InstanceId,$_.Status)) }"
    try:
        result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], {"reason": "local-video-inventory-failed", "error_type": type(exc).__name__, "absence_claim": False}
    if result.returncode != 0:
        return [], {"reason": "local-video-inventory-failed", "returncode": result.returncode, "absence_claim": False}
    interfaces = _parse_windows_video_devices(result.stdout)
    return _group_local_video_sources(interfaces), None


def _classify_announced_service(protocol: str, item: dict) -> dict | None:
    """Classify only what the remote service explicitly announces; never infer physical make/model."""
    if protocol == "WS-Discovery":
        types = set(item.get("types") or [])
        if any(value.endswith("NetworkVideoTransmitter") for value in types):
            return {
                "class": "video-source-service",
                "confidence": "HIGH",
                "basis": "announced-ws-discovery-type",
                "physical_identity": "UNKNOWN",
            }
        if any(value.endswith("Computer") for value in types):
            return {
                "class": "computer-service",
                "confidence": "HIGH",
                "basis": "announced-ws-discovery-type",
                "physical_identity": "UNKNOWN",
            }
    if protocol == "SSDP":
        server = item.get("server") or ""
        if "Chromecast/" in server:
            return {
                "class": "media-service",
                "confidence": "HIGH",
                "basis": "announced-ssdp-server",
                "physical_identity": "UNKNOWN",
            }
    return None

def _correlate_network_evidence(neighbors: list[dict], ssdp: list[dict], ws: list[dict]) -> list[dict]:
    """Join observed signals by address while keeping identity claims explicit and conservative."""
    hosts = {}
    def row(address):
        return hosts.setdefault(address, {
            "address": address,
            "neighbor": None,
            "announced_protocols": [],
            "service_hints": [],
            "identity_status": "UNKNOWN",
        })
    for item in neighbors:
        row(item["address"])["neighbor"] = item
    for protocol, items in (("SSDP", ssdp), ("WS-Discovery", ws)):
        for item in items:
            host = row(item["address"])
            if protocol not in host["announced_protocols"]:
                host["announced_protocols"].append(protocol)
            hint = {"protocol": protocol}
            for key in ("server", "location", "types", "scopes", "xaddrs", "endpoint", "observed_rounds", "rounds_attempted"):
                if item.get(key):
                    hint[key] = item[key]
            classification = _classify_announced_service(protocol, item)
            if classification:
                hint["classification"] = classification
            if hint not in host["service_hints"]:
                host["service_hints"].append(hint)
    return [hosts[key] for key in sorted(hosts, key=ipaddress.ip_address)]


def _network_contains_local_host(network) -> bool:
    return any(ipaddress.ip_address(address) in network for address in _local_ipv4_addresses(network))


def _local_video_observation(network) -> dict | None:
    if not _network_contains_local_host(network):
        return None
    sources, limitation = discover_local_video_sources()
    return _obs(
        f"Local OS inventory observed {len(sources)} logical video source(s)",
        {"kind": "local-video-sources", "sources": sources, "limitation": limitation,
         "traffic_generated": False, "capture_opened": False,
         "absence_claim": False if limitation else None},
    )

def recon_network(target: Target):
    from .controls import checkpoint
    network = ipaddress.ip_network(target.value, strict=False)
    observations = [_obs("Network scope characterized",
        {"kind":"network","network":str(network),"version":network.version,
         "address_count":network.num_addresses})]
    local_video = _local_video_observation(network)
    if local_video:
        observations.append(local_video)
    neighbors = _local_neighbor_evidence(network)
    if neighbors:
        observations.append(_obs(
            f"Local neighbor evidence observed {len(neighbors)} in-scope host(s) before active probes",
            {"kind":"network-neighbors","hosts":neighbors,"provenance":"local-neighbor-cache",
             "traffic_generated":False,"identity_inferred":False},
        ))
    from .controls import current_controls
    if current_controls.get().profile == "passive":
        observations.append(_obs(
            "Passive network assessment stopped after local neighbor evidence; no active probes were sent",
            {"kind":"decision","reason":"passive-network-local-evidence-only","traffic_generated":False},
        ))
        return observations, ("host-discovery-partial",) if neighbors else ()
    announced = _discover_ssdp(network)
    if announced:
        responders = sorted({item["address"] for item in announced})
        observations.append(_obs(
            f"SSDP discovery observed {len(responders)} responder(s) with {len(announced)} service announcement(s)",
            {"kind":"announced-services","protocol":"SSDP","responders":responders,"services":announced,
             "traffic_generated":True,"query_count":len(_local_ipv4_addresses(network) or [None]),
             "identity_inferred":False},
        ))
    ws_devices = _discover_ws(network)
    observations.append(_obs(
        f"WS-Discovery observed {len(ws_devices)} ProbeMatch response(s)",
        {"kind":"announced-services","protocol":"WS-Discovery","services":ws_devices,
         "traffic_generated":True,"query_count":len(_local_ipv4_addresses(network) or [None]),
         "identity_inferred":False,
         "negative_claim":"no-response-does-not-exclude-non-discoverable-device"},
    ))
    correlated = _correlate_network_evidence(neighbors, announced, ws_devices)
    if correlated:
        observations.append(_obs(
            f"Correlated {len(correlated)} observed network host record(s) without forcing identity",
            {"kind":"network-host-correlation","hosts":correlated,"identity_inferred":False},
        ))
    if network.num_addresses > 256:
        observations.append(_obs("Active host discovery deferred: network exceeds safe core sweep budget",
            {"kind":"decision","reason":"network-budget","max_active_hosts":256,
             "address_count":network.num_addresses}))
        return observations, ()
    live = []
    ports = (80,443,22,445)
    for address in network.hosts():
        checkpoint(pace=True)
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
    inventory_files, _, _, inventory_errors = _inventory_tree(path)
    files = [p for p in inventory_files if _is_first_party_path(p, path)
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
