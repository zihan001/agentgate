"""Secrets detector — flags AWS keys, GitHub tokens, private keys, and password patterns in any parameter value."""

from __future__ import annotations

import re

from agentgate.detectors._util import extract_strings
from agentgate.models import DetectorResult, ToolCall


_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS Access Key ID (case-sensitive, exact format)
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    # AWS Secret Key assignment (case-insensitive key name)
    (
        re.compile(
            r"(?:aws_secret_access_key|aws_secret_key|AWS_SECRET_ACCESS_KEY)"
            r"\s*[=:]\s*\S+",
            re.IGNORECASE,
        ),
        "AWS secret access key assignment",
    ),
    # GitHub tokens (case-sensitive prefix, exact format)
    (re.compile(r"(?:ghp_|gho_|ghs_|ghu_)[A-Za-z0-9]{36}"), "GitHub token"),
    (re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "GitHub fine-grained PAT"),
    # PEM private key header
    (
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----"
        ),
        "PEM private key",
    ),
    # Generic password/secret assignment (case-insensitive)
    (
        re.compile(
            r"(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|auth_token)"
            r"\s*[=:]\s*\S+",
            re.IGNORECASE,
        ),
        "password/secret assignment",
    ),
    # Slack tokens
    (re.compile(r"xox[bpors]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    # Bearer token
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer authorization token"),
    # Stripe keys
    (re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"), "Stripe API key"),
]


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for secret/credential patterns.

    Returns DetectorResult with matched=True on first pattern hit.
    """
    strings = extract_strings(tool_call.arguments)

    for param_path, value in strings:
        for pattern, label in _SECRET_PATTERNS:
            if pattern.search(value):
                return DetectorResult(
                    matched=True,
                    detector_name="secrets_in_params",
                    detail=f"Secret detected in param '{param_path}': {label}",
                )

    return DetectorResult(matched=False, detector_name="secrets_in_params")
