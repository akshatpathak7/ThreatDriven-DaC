from src.threat_intel import load_threat_intel, normalize_indicator


def test_load_threat_intel_deduplicates_iocs() -> None:
    store = load_threat_intel("data/threat_intel")

    assert store.find("203.0.113.66", "ip") is not None
    assert len([ioc for ioc in store.indicators if ioc.value == "203.0.113.66"]) == 1


def test_ioc_matching_and_normalization() -> None:
    store = load_threat_intel("data/threat_intel")

    assert normalize_indicator(" Evil.Example ", "domain") == "evil.example"
    assert store.find("192.0.2.44", "ip").threat_type == "suspicious_cloud_api_activity"

