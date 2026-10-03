from surface_recon.redaction import minimize, redact_text


def test_redacts_bearer_token():
    result = redact_text("Authorization: Bearer secret-value")
    assert "secret-value" not in result
    assert "[REDACTED]" in result


def test_redacts_nested_sensitive_values():
    result = minimize({"output": ["token=abc123", "safe"]})
    assert result == {"output": ["token=[REDACTED]", "safe"]}

def test_redacts_sensitive_mapping_values():
    result = minimize({
        "token": "secret123",
        "password": "hunter2",
        "safe": "visible",
    })
    assert result == {
        "token": "[REDACTED]",
        "password": "[REDACTED]",
        "safe": "visible",
    }


def test_redacts_session_identifiers_inside_urls():
    value = "http://example.test/app;jsessionid=ABC123?access_token=SECRET"
    result = redact_text(value)
    assert "ABC123" not in result
    assert "SECRET" not in result
    assert result.count("[REDACTED]") == 2
    assert "WOLFSECRET" not in redact_text("http://example.test/x;WEBWOLFSESSION=WOLFSECRET")
