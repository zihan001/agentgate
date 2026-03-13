"""Tests for SSRF private IP detector."""

from agentgate.detectors.ssrf import detect
from agentgate.models import ToolCall


def _call(arguments: dict) -> ToolCall:
    """Build a ToolCall with the given arguments."""
    return ToolCall(tool_name="fetch_url", arguments=arguments, call_id=1)


# ── Positive cases (8) — must detect ────────────────────────────────────


def test_aws_metadata_endpoint():
    result = detect(
        _call({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
    )
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "169.254.169.254" in result.detail


def test_private_10_network():
    result = detect(_call({"url": "http://10.0.0.1/admin"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "10.0.0.1" in result.detail


def test_private_172_network():
    result = detect(_call({"url": "http://172.16.0.1/internal"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "172.16.0.1" in result.detail


def test_private_192_network():
    result = detect(_call({"url": "http://192.168.1.1/config"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "192.168.1.1" in result.detail


def test_loopback_127():
    result = detect(_call({"url": "http://127.0.0.1:8080/"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "127.0.0.1" in result.detail


def test_zero_address():
    result = detect(_call({"url": "http://0.0.0.0/"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "0.0.0.0" in result.detail


def test_ipv6_loopback():
    result = detect(_call({"url": "http://[::1]:3000/"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "::1" in result.detail


def test_bare_private_ip():
    result = detect(_call({"target": "192.168.1.1"}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "192.168.1.1" in result.detail


# ── Negative cases (7) — must NOT detect ────────────────────────────────


def test_public_api_url():
    result = detect(_call({"url": "https://api.github.com/repos"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


def test_public_dns_ip():
    result = detect(_call({"url": "https://8.8.8.8/dns-query"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


def test_public_website():
    result = detect(_call({"url": "https://www.example.com/page"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


def test_non_url_string():
    result = detect(_call({"path": "/data/workspace/report.csv"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


def test_numeric_string_not_ip():
    result = detect(_call({"limit": "192"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


def test_public_ip_bare():
    result = detect(_call({"host": "151.101.1.69"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


def test_empty_arguments():
    result = detect(_call({}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"


# ── Edge cases (2) ──────────────────────────────────────────────────────


def test_nested_url_param():
    result = detect(_call({"options": {"endpoint": "http://10.0.0.1/api"}}))
    assert result.matched is True
    assert result.detector_name == "ssrf_private_ip"
    assert "options.endpoint" in result.detail


def test_url_with_path_only():
    result = detect(_call({"url": "/api/v1/users"}))
    assert result.matched is False
    assert result.detector_name == "ssrf_private_ip"
