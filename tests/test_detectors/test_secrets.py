"""Tests for the secrets_in_params detector."""

from __future__ import annotations

from agentgate.detectors.secrets import detect
from agentgate.models import ToolCall


def _call(arguments: dict) -> ToolCall:
    return ToolCall(tool_name="test_tool", arguments=arguments, call_id="test-1")


# ---------------------------------------------------------------------------
# Positive cases (8 tests — must all match)
# ---------------------------------------------------------------------------


def test_aws_access_key_id():
    result = detect(_call({"body": "key is AKIA1234567890ABCDEF"}))
    assert result.matched
    assert result.detector_name == "secrets_in_params"
    assert "AWS access key ID" in result.detail


def test_github_pat_classic():
    result = detect(_call({"token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"}))
    assert result.matched
    assert "GitHub token" in result.detail


def test_github_fine_grained_pat():
    pat = f"github_pat_{'A' * 22}_{'B' * 59}"
    result = detect(_call({"auth": pat}))
    assert result.matched
    assert "GitHub fine-grained PAT" in result.detail


def test_rsa_private_key():
    result = detect(_call({"data": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}))
    assert result.matched
    assert "PEM private key" in result.detail


def test_generic_private_key():
    result = detect(_call({"data": "-----BEGIN PRIVATE KEY-----\nMIIE..."}))
    assert result.matched
    assert "PEM private key" in result.detail


def test_password_assignment():
    result = detect(_call({"config": "database_password=hunter2"}))
    assert result.matched
    assert "password/secret assignment" in result.detail


def test_secret_in_nested_param():
    result = detect(_call({"outer": {"inner": "api_key=sk_12345"}}))
    assert result.matched
    assert result.detector_name == "secrets_in_params"


def test_slack_token():
    result = detect(_call({"webhook": "xoxb-1234-5678-abcdefghij"}))
    assert result.matched
    assert "Slack token" in result.detail


# ---------------------------------------------------------------------------
# Negative cases (7 tests — must all NOT match)
# ---------------------------------------------------------------------------


def test_normal_business_text():
    result = detect(_call({"body": "Please review the Q4 sales report"}))
    assert not result.matched
    assert result.detector_name == "secrets_in_params"


def test_word_password_in_prose():
    result = detect(_call({"body": "Please reset your password at the portal"}))
    assert not result.matched


def test_short_alphanumeric():
    result = detect(_call({"token": "abc123"}))
    assert not result.matched


def test_wrong_aws_prefix():
    result = detect(_call({"key": "AKID1234567890ABCDEF"}))
    assert not result.matched


def test_uuid_not_flagged():
    result = detect(_call({"id": "550e8400-e29b-41d4-a716-446655440000"}))
    assert not result.matched


def test_file_path_with_key():
    result = detect(_call({"path": "/data/workspace/key-metrics.csv"}))
    assert not result.matched


def test_base64_without_prefix():
    result = detect(_call({"data": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="}))
    assert not result.matched


# ---------------------------------------------------------------------------
# Edge cases (2 tests)
# ---------------------------------------------------------------------------


def test_aws_key_in_url():
    result = detect(_call({"url": "https://s3.amazonaws.com/?AWSAccessKeyId=AKIA1234567890ABCDEF"}))
    assert result.matched
    assert "AWS access key ID" in result.detail


def test_empty_arguments():
    result = detect(_call({}))
    assert not result.matched
    assert result.detector_name == "secrets_in_params"


def test_stripe_secret_key():
    # Use sk_test_ prefix (not sk_live_) to avoid GitHub push protection false positive
    result = detect(_call({"key": "sk_test_" + "a" * 24}))
    assert result.matched
    assert "Stripe API key" in result.detail


def test_bearer_token():
    result = detect(_call({"header": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"}))
    assert result.matched
    assert "Bearer authorization token" in result.detail
