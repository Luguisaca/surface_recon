from surface_recon.surface_model import merge_service_surface


def test_same_endpoint_is_one_semantic_surface_with_preserved_provenance():
    observations = [
        {"source": "surface-recon-core", "evidence": {
            "kind": "ports", "host": "192.0.2.10",
            "reachable": [{"port": 22, "service_hint": "ssh"}],
        }},
        {"source": "surface-recon-core", "evidence": {
            "kind": "service-fingerprints", "host": "192.0.2.10",
            "services": [{"port": 22, "service_hint": "ssh", "banner": "SSH-2.0-test"}],
        }},
        {"source": "nmap", "evidence": {
            "kind": "nmap-surface", "hosts": [{
                "addresses": ["192.0.2.10"],
                "services": [{"protocol": "tcp", "port": 22, "service": "ssh",
                              "product": "Dropbear", "version": "2024.86", "method": "probed"}],
            }],
        }},
    ]

    surface = merge_service_surface(observations, "192.0.2.10")

    assert len(surface) == 1
    endpoint = surface[0]
    assert endpoint["value"] == "192.0.2.10:22/tcp"
    assert endpoint["identity_confidence"] == "fingerprinted"
    assert endpoint["service"] == "ssh"
    assert endpoint["product"] == "Dropbear"
    assert set(endpoint["evidence_sources"]) == {"surface-recon-core", "nmap"}
    assert len(endpoint["evidence"]) == 3


def test_open_port_hint_is_not_upgraded_to_verified_fingerprint():
    surface = merge_service_surface([{
        "source": "nmap", "evidence": {"kind": "nmap-surface", "hosts": [{
            "addresses": ["192.0.2.20"],
            "services": [{"protocol": "tcp", "port": 3306, "service": "mysql", "method": "table"}],
        }]}
    }], "192.0.2.20")

    assert surface[0]["identity_confidence"] == "provider-hint"
    assert surface[0]["product"] is None


def test_priority_is_evidence_driven_not_a_vulnerability_claim():
    from surface_recon.surface_model import prioritize_service_surface
    surface = [{
        "type":"network-service","value":"192.0.2.10:3306/tcp","service":"mysql",
        "identity_confidence":"fingerprinted","evidence_sources":["nmap"],"evidence":[],
    }, {
        "type":"network-service","value":"192.0.2.10:9999/tcp","service":None,
        "identity_confidence":"reachable","evidence_sources":["surface-recon-core"],"evidence":[],
    }]
    prioritized = prioritize_service_surface(surface)
    assert prioritized[0]["service_family"] == "database"
    assert prioritized[0]["review_priority"] == "high"
    assert "validate intended exposure" in prioritized[0]["priority_reason"]
    assert prioritized[1]["service_family"] == "unknown"
    assert "fingerprint before" in prioritized[1]["priority_reason"]
    assert all("vulnerab" not in item["priority_reason"].lower() for item in prioritized)
