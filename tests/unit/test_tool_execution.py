import json

from surface_recon.model import ScopeState, Target
from surface_recon.process import ProcessResult
from surface_recon.tooling import ToolCandidate, execute_tool


def _target():
    return Target("t1", "https://example.test", ScopeState.AUTHORIZED, target_type="url")


def test_httpx_executes_with_structured_safe_arguments(monkeypatch):
    tool = ToolCandidate("httpx", "http-recon", ("httpx",), "probe", ("Linux",), "MIT", ("http-probing", "technology-fingerprinting"), "/bin/httpx")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = tuple(args)
        captured["kwargs"] = kwargs
        line = json.dumps({"url": "https://example.test", "status_code": 200, "title": "Example"})
        return ProcessResult(tuple(args), 0, line + "\n", "")

    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)
    result = execute_tool(tool, _target())

    assert captured["args"] == ("/bin/httpx", "-u", "https://example.test", "-json", "-silent", "-no-stdin", "-duc")
    assert captured["kwargs"]["action_kind"] == "recon"
    assert result.succeeded
    assert result.observations[0]["evidence"]["status_code"] == 200


def test_nuclei_uses_non_intrusive_default_and_normalizes_jsonl(monkeypatch, tmp_path):
    tool = ToolCandidate("nuclei", "http-recon", ("nuclei",), "templates", ("Linux",), "MIT", ("template-detection",), "/bin/nuclei")
    template = tmp_path / "safe.yaml"
    template.write_text("id: safe-test\n", encoding="utf-8")
    monkeypatch.setenv("SURFACE_RECON_NUCLEI_TEMPLATES", str(template))

    def fake_run(args, **kwargs):
        assert "-etags" in args
        excluded = args[args.index("-etags") + 1]
        assert "intrusive" in excluded and "dos" in excluded and "fuzz" in excluded
        assert "-itags" not in args
        assert args[args.index("-rl") + 1] == "5"
        assert args[args.index("-c") + 1] == "2"
        assert args[args.index("-bs") + 1] == "2"
        assert args[args.index("-timeout") + 1] == "5"
        assert args[args.index("-retries") + 1] == "0"
        line = json.dumps({
            "template-id": "missing-header",
            "info": {"name": "Missing Header", "severity": "info"},
            "matched-at": "https://example.test",
            "extracted-results": ["/admin"],
        })
        return ProcessResult(tuple(args), 0, line + "\n", "")

    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)
    result = execute_tool(tool, _target())

    assert result.succeeded
    assert result.observations[0]["description"] == "Nuclei: Missing Header"
    assert result.observations[0]["evidence"]["template_id"] == "missing-header"
    assert result.observations[0]["evidence"]["extracted_results"] == ["/admin"]
    assert "content-discovery" in result.covered_subcapabilities


def test_nuclei_does_not_download_missing_templates(monkeypatch, tmp_path):
    monkeypatch.setattr("surface_recon.tooling.Path.home", lambda: tmp_path)
    tool = ToolCandidate("nuclei", "http-recon", ("nuclei",), "templates", ("Windows",), "MIT", ("template-detection",), "C:/tools/nuclei.exe")
    monkeypatch.delenv("SURFACE_RECON_NUCLEI_TEMPLATES", raising=False)
    monkeypatch.setattr(
        "surface_recon.tooling.run_process",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not execute")),
    )

    result = execute_tool(tool, _target())

    assert not result.succeeded
    assert "no templates were downloaded automatically" in result.error



def test_trivy_uses_local_databases_and_normalizes_vulnerabilities(monkeypatch):
    tool = ToolCandidate(
        "trivy", "repository-recon", ("trivy",), "scan", ("Windows",),
        "Apache-2.0", ("secret-detection", "dependency-analysis"), "C:/tools/trivy.exe",
    )
    target = Target("t1", ".", ScopeState.AUTHORIZED, target_type="repository")

    def fake_run(args, **kwargs):
        assert args[1:5] == ("fs", "--scanners", "vuln,secret", "--skip-db-update")
        report = {
            "Results": [{
                "Target": "uv.lock",
                "Packages": [{"Name": "demo"}],
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2099-0001",
                    "PkgName": "demo",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.1",
                    "Severity": "HIGH",
                }],
            }]
        }
        return ProcessResult(tuple(args), 0, json.dumps(report), "")

    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)
    result = execute_tool(tool, target)

    assert result.succeeded
    assert result.observations[0]["finding"] is True
    assert result.observations[0]["evidence"]["vulnerability_id"] == "CVE-2099-0001"
    assert set(result.covered_subcapabilities) == {"secret-detection", "dependency-analysis"}


def test_nmap_host_provider_uses_full_tcp_range_and_normalizes_surface(monkeypatch):
    tool = ToolCandidate("nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
                         ("host-discovery","port-discovery","service-fingerprinting"), "/usr/bin/nmap")
    target = Target("h", "192.0.2.10", ScopeState.AUTHORIZED, target_type="host")
    xml = """<?xml version="1.0"?><nmaprun><host><address addr="192.0.2.10"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
    <service name="https" product="nginx" version="1.25"/></port></ports></host></nmaprun>"""
    def fake_run(args, **kwargs):
        assert "-p-" in args
        assert "-sV" in args
        assert kwargs["timeout"] == 300.0
        return ProcessResult(tuple(args), 0, xml, "")
    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)
    result = execute_tool(tool, target)
    assert result.succeeded
    assert result.observations[0]["evidence"]["full_tcp_range_tested"] is True
    assert result.observations[0]["evidence"]["hosts"][0]["services"][0]["port"] == 443
    assert "port-discovery" in result.covered_subcapabilities


def test_nmap_network_provider_discovers_hosts_then_deepens_full_tcp(monkeypatch):
    tool = ToolCandidate("nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
                         ("host-discovery","port-discovery","service-fingerprinting"), "/usr/bin/nmap")
    target = Target("n", "192.0.2.0/30", ScopeState.AUTHORIZED, target_type="network")
    discovery_xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.1"/></host></nmaprun>"""
    deep_xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.1"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH"/></port></ports></host></nmaprun>"""
    calls = []
    def fake_run(args, **kwargs):
        calls.append(tuple(args))
        if "-sn" in args:
            return ProcessResult(tuple(args), 0, discovery_xml, "")
        assert "-p-" in args
        assert "192.0.2.1" in args
        return ProcessResult(tuple(args), 0, deep_xml, "")
    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)

    result = execute_tool(tool, target)

    assert result.succeeded
    assert len(calls) == 2
    assert "-sn" in calls[0] and "-p-" not in calls[0]
    assert "-p-" in calls[1] and "-sV" in calls[1]
    assert "--open" not in calls[1]  # preserve hosts with zero open ports in XML
    assert set(result.covered_subcapabilities) == {
        "host-discovery", "port-discovery", "service-fingerprinting"
    }
    assert result.observations[-1]["evidence"]["full_tcp_range_tested"] is True


def test_nmap_network_provider_does_not_deepen_nondiscriminating_discovery(monkeypatch):
    tool = ToolCandidate("nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
                         ("host-discovery","port-discovery","service-fingerprinting"), "/usr/bin/nmap")
    target = Target("n", "192.0.2.0/24", ScopeState.AUTHORIZED, target_type="network")
    discovery_xml = """<nmaprun>
    <host><status state="up"/><address addr="192.0.2.0"/></host>
    <host><status state="up"/><address addr="192.0.2.5"/></host>
    <host><status state="up"/><address addr="192.0.2.255"/></host>
    </nmaprun>"""
    calls = []
    def fake_run(args, **kwargs):
        calls.append(tuple(args))
        return ProcessResult(tuple(args), 0, discovery_xml, "")
    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)

    result = execute_tool(tool, target)

    assert result.succeeded
    assert len(calls) == 1
    assert result.covered_subcapabilities == ("host-discovery",)
    assert result.observations[-1]["evidence"]["reason"] == "provider-host-discovery-nondiscriminating"


def test_nuclei_directory_selection_stays_http_and_token_exact(monkeypatch, tmp_path):
    root = tmp_path / "templates"
    http = root / "http" / "misc"
    cloud = root / "cloud" / "aws"
    http.mkdir(parents=True); cloud.mkdir(parents=True)
    good = http / "nginx-check.yaml"
    wrong_scope = cloud / "nginx-check.yaml"
    wrong_token = http / "nginxplus-check.yaml"
    for path in (good, wrong_scope, wrong_token):
        path.write_text("id: test\n", encoding="utf-8")
    monkeypatch.setenv("SURFACE_RECON_NUCLEI_TEMPLATES", str(root))
    tool = ToolCandidate("nuclei", "http-recon", ("nuclei",), "templates",
                         ("Linux",), "MIT", ("template-detection",), "/bin/nuclei")
    target = _target()
    target.technology_hints = ["Server: nginx/1.26.0"]

    def fake_run(args, **kwargs):
        selected = [args[i + 1] for i, x in enumerate(args) if x == "-t"]
        assert selected == [str(good)]
        return ProcessResult(tuple(args), 0, "", "")
    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)

    result = execute_tool(tool, target)
    assert result.succeeded


def test_nmap_parser_does_not_promote_mac_address_as_host_target():
    from surface_recon.tooling import _parse_nmap_hosts

    xml = """<nmaprun><host><status state="up"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <address addr="192.0.2.15" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/>
    <service name="https"/></port></ports></host></nmaprun>"""

    hosts = _parse_nmap_hosts(xml)

    assert hosts[0]["addresses"] == ["192.0.2.15"]
    assert hosts[0]["services"][0]["port"] == 443


def test_nmap_network_does_not_claim_full_coverage_when_deep_host_is_missing(monkeypatch):
    tool = ToolCandidate("nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
                         ("host-discovery","port-discovery","service-fingerprinting"), "/usr/bin/nmap")
    target = Target("n", "192.0.2.0/30", ScopeState.AUTHORIZED, target_type="network")
    discovery_xml = """<nmaprun>
    <host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host>
    <host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/></host>
    </nmaprun>"""
    deep_xml = """<nmaprun><host><status state="up"/>
    <address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>"""
    def fake_run(args, **kwargs):
        xml = discovery_xml if "-sn" in args else deep_xml
        return ProcessResult(tuple(args), 0, xml, "")
    monkeypatch.setattr("surface_recon.tooling.run_process", fake_run)

    result = execute_tool(tool, target)

    assert result.succeeded
    assert "port-discovery" not in result.covered_subcapabilities
    assert "port-discovery-partial" in result.covered_subcapabilities
    surface = result.observations[-1]["evidence"]
    assert surface["full_tcp_range_tested"] is False
    assert surface["hosts_missing_from_deepening"] == ["192.0.2.2"]


def test_nmap_parser_preserves_ssl_tunnel_for_nondefault_https(monkeypatch):
    tool = ToolCandidate("nmap", "host-recon", ("nmap",), "scan", ("Linux",), "NPSL",
                         ("host-discovery", "port-discovery", "service-fingerprinting"), "/usr/bin/nmap")
    target = Target("h", "192.0.2.10", ScopeState.AUTHORIZED, target_type="host")
    xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="9443"><state state="open"/>
    <service name="http" tunnel="ssl" product="nginx"/></port></ports></host></nmaprun>"""
    monkeypatch.setattr(
        "surface_recon.tooling.run_process",
        lambda args, **kwargs: ProcessResult(tuple(args), 0, xml, ""),
    )

    result = execute_tool(tool, target)

    service = result.observations[0]["evidence"]["hosts"][0]["services"][0]
    assert service["service"] == "http"
    assert service["tunnel"] == "ssl"
