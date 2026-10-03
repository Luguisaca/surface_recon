from surface_recon.assessment import assess_targets

def test_heterogeneous_targets_are_processed_independently():
    assessment = assess_targets([
        "https://example.test",
        "192.0.2.10",
        "./controlled-project",
    ])

    assert len(assessment.targets) == 3
    assert [t.target_type for t in assessment.targets] == [
        "url", "host", "path"
    ]
    assert len(assessment.coverage) == 3
