# Issue #25: `secrets_in_params` Detector — Implementation Spec

**Status:** Ready to build  
**Depends on:** None (parallel with #21–#24)  
**Blocks:** #26 (wire detectors into engine)  
**Ref:** MVP Spec §3 (detector table), §6 AT-2, §2 S2, §11 Risk 2  

---

## 1. What This Does

Scans every string value in a tool call's `arguments` dict (recursively, including nested dicts and lists) for credential and secret patterns. Returns `DetectorResult(matched=True)` on the first match.

This is the detector behind acceptance test AT-2 (credential exfiltration block) and success criterion S2 ("zero credential/secret values pass through tool call arguments when the `secrets_in_params` detector is enabled").

---

## 2. Exact Patterns

Seven pattern categories covering the highest-value secret types. All patterns use exact-format regexes to minimize false positives (Spec Risk 2). No broad alphanumeric matchers.

### Category 1: AWS Access Keys

| Pattern | Regex | Notes |
|---------|-------|-------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | Always starts with `AKIA`, exactly 20 chars total |
| AWS Secret Access Key candidate | `(?:aws_secret_access_key\|aws_secret_key\|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S+` | Key name + assignment, not standalone base64 strings |

**Design choice:** Only flag `AKIA...` standalone (it's a unique prefix with zero legitimate non-AWS uses). For secret keys, require the key name prefix to avoid false positives on arbitrary base64 strings.

### Category 2: GitHub Tokens

| Pattern | Regex | Notes |
|---------|-------|-------|
| GitHub PAT (classic) | `ghp_[A-Za-z0-9]{36}` | Fine-grained and classic PATs |
| GitHub OAuth token | `gho_[A-Za-z0-9]{36}` | OAuth access tokens |
| GitHub App server token | `ghs_[A-Za-z0-9]{36}` | Server-to-server tokens |
| GitHub App user token | `ghu_[A-Za-z0-9]{36}` | User-to-server tokens |
| GitHub fine-grained PAT | `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` | Newer format with underscore separator |

**Implementation:** Single combined pattern: `(?:ghp_|gho_|ghs_|ghu_)[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`

### Category 3: Private Keys (PEM)

| Pattern | Regex | Notes |
|---------|-------|-------|
| PEM private key header | `-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----` | Covers RSA, DSA, EC, OpenSSH, and encrypted PEM formats |

**Design choice:** Match on the `BEGIN...PRIVATE KEY` header line. This is the standard PEM envelope and has zero legitimate non-key uses in tool call parameters.

### Category 4: Generic Password Assignment

| Pattern | Regex | Notes |
|---------|-------|-------|
| Password/secret assignment | `(?:password\|passwd\|pwd\|secret\|api_key\|apikey\|api_secret\|access_token\|auth_token)\s*[=:]\s*\S+` | Key name followed by `=` or `:` and a non-whitespace value |

**Design choice:** Require `key=value` format. Do NOT flag the word "password" alone — that would hit every password reset email, documentation string, and UI label. The `=` or `:` operator is the signal that a credential is being transmitted, not just mentioned.

### Category 5: Slack Tokens

| Pattern | Regex | Notes |
|---------|-------|-------|
| Slack bot/user/workspace token | `xox[bpors]-[A-Za-z0-9-]{10,}` | Covers `xoxb-`, `xoxp-`, `xoxo-`, `xoxr-`, `xoxs-` |

### Category 6: Generic API Key Header Values

| Pattern | Regex | Notes |
|---------|-------|-------|
| Bearer token in header value | `Bearer\s+[A-Za-z0-9\-._~+/]+=*` | Authorization header values being passed as params |

### Category 7: Stripe Keys

| Pattern | Regex | Notes |
|---------|-------|-------|
| Stripe secret/publishable key | `(?:sk\|pk)_(?:live\|test)_[A-Za-z0-9]{24,}` | Stripe API keys |

---

## 3. What NOT to Flag

These are explicit false-positive exclusions to test against:

- The word "password" in normal text (e.g., "Please reset your password")
- Short alphanumeric strings (e.g., `abc123`, `token`, `key`)
- Strings that look key-like but don't match exact format (e.g., `AKID1234` — wrong prefix)
- Base64-encoded data without a key prefix (e.g., `aGVsbG8gd29ybGQ=`)
- UUIDs (e.g., `550e8400-e29b-41d4-a716-446655440000`)
- Normal email addresses
- File paths that happen to contain "key" (e.g., `/data/workspace/key-metrics.csv`)

---

## 4. Implementation

### File: `src/agentgate/detectors/secrets.py`

**Structure:** Follow the exact pattern established by `sql_injection.py`, `path_traversal.py`, `command_injection.py`, and `ssrf.py`:

1. `_extract_strings(arguments, prefix)` — recursive string extraction (copy from existing detectors, or factor out into a shared utility later in #26)
2. `_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]]` — compiled regex + label pairs
3. `detect(tool_call: ToolCall) -> DetectorResult` — iterate strings, iterate patterns, return on first match

**Key decisions:**

- All regexes use `re.IGNORECASE` for the password/secret assignment patterns only. AWS keys and GitHub tokens are case-sensitive by format — do NOT use `re.IGNORECASE` on those.
- Use `re.search()` (not `re.match()`) — secrets can appear anywhere in a string value, not just at the start.
- Short-circuit on first match (same as all other detectors).
- `detector_name` in result: `"secrets_in_params"`

### Pattern list (implementation order)

```python
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # AWS Access Key ID (case-sensitive, exact format)
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),

    # AWS Secret Key assignment (case-insensitive key name)
    (re.compile(
        r"(?:aws_secret_access_key|aws_secret_key|AWS_SECRET_ACCESS_KEY)"
        r"\s*[=:]\s*\S+", re.IGNORECASE
    ), "AWS secret access key assignment"),

    # GitHub tokens (case-sensitive prefix, exact format)
    (re.compile(r"(?:ghp_|gho_|ghs_|ghu_)[A-Za-z0-9]{36}"), "GitHub token"),
    (re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "GitHub fine-grained PAT"),

    # PEM private key header
    (re.compile(
        r"-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----"
    ), "PEM private key"),

    # Generic password/secret assignment (case-insensitive)
    (re.compile(
        r"(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|auth_token)"
        r"\s*[=:]\s*\S+", re.IGNORECASE
    ), "password/secret assignment"),

    # Slack tokens
    (re.compile(r"xox[bpors]-[A-Za-z0-9\-]{10,}"), "Slack token"),

    # Bearer token
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer authorization token"),

    # Stripe keys
    (re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"), "Stripe API key"),
]
```

---

## 5. Test Plan

### File: `tests/test_detectors/test_secrets.py`

Follow the established pattern from other detector test files: 16–17 tests organized as positive, negative, and edge cases. All tests are sync, no I/O.

### Positive Cases (8 tests — must all match)

| # | Test name | Input | Why it matters |
|---|-----------|-------|----------------|
| P1 | `test_aws_access_key_id` | `{"body": "key is AKIA1234567890ABCDEF"}` | Exact AT-2 scenario from spec |
| P2 | `test_github_pat_classic` | `{"token": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"}` | Classic GitHub PAT format |
| P3 | `test_github_fine_grained_pat` | `{"auth": "github_pat_<22chars>_<59chars>"}` | Newer GitHub PAT format |
| P4 | `test_rsa_private_key` | `{"data": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}` | PEM key header in body |
| P5 | `test_generic_private_key` | `{"data": "-----BEGIN PRIVATE KEY-----\nMIIE..."}` | PKCS#8 format (no algorithm prefix) |
| P6 | `test_password_assignment` | `{"config": "database_password=hunter2"}` | Password in config string |
| P7 | `test_secret_in_nested_param` | `{"outer": {"inner": "api_key=sk_12345"}}` | Recursive extraction works |
| P8 | `test_slack_token` | `{"webhook": "xoxb-1234-5678-abcdefghij"}` | Slack bot token |

### Negative Cases (7 tests — must all NOT match)

| # | Test name | Input | Why it must not fire |
|---|-----------|-------|---------------------|
| N1 | `test_normal_business_text` | `{"body": "Please review the Q4 sales report"}` | Normal text, no secrets |
| N2 | `test_word_password_in_prose` | `{"body": "Please reset your password at the portal"}` | "password" without `=`/`:` assignment |
| N3 | `test_short_alphanumeric` | `{"token": "abc123"}` | Too short, no prefix match |
| N4 | `test_wrong_aws_prefix` | `{"key": "AKID1234567890ABCDEF"}` | Wrong prefix (`AKID` not `AKIA`) |
| N5 | `test_uuid_not_flagged` | `{"id": "550e8400-e29b-41d4-a716-446655440000"}` | UUID looks key-like but isn't |
| N6 | `test_file_path_with_key` | `{"path": "/data/workspace/key-metrics.csv"}` | "key" in a file path is not a secret |
| N7 | `test_base64_without_prefix` | `{"data": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q="}` | Raw base64 should not trigger |

### Edge Cases (2 tests)

| # | Test name | Input | Expected |
|---|-----------|-------|----------|
| E1 | `test_aws_key_in_url` | `{"url": "https://s3.amazonaws.com/?AWSAccessKeyId=AKIA1234567890ABCDEF"}` | Match — key embedded in URL param |
| E2 | `test_empty_arguments` | `{}` | No match — empty arguments should not error |

**Total: 17 tests** (matching the count of other detector test files).

---

## 6. Acceptance Criteria

- [ ] `detect()` returns `DetectorResult(matched=True, detector_name="secrets_in_params", detail=...)` for all 8 positive test cases
- [ ] `detect()` returns `DetectorResult(matched=False, detector_name="secrets_in_params")` for all 7 negative test cases
- [ ] Both edge cases pass
- [ ] All 17 tests pass with `uv run pytest tests/test_detectors/test_secrets.py`
- [ ] Zero false positives on the 10 benign evaluation scenarios (B1–B10) from Spec §12 when this detector is enabled — specifically B8 ("Read file with SQL-like content") and B9 ("Read file with path-like content") should not trigger this detector
- [ ] `detector_name` field is exactly `"secrets_in_params"` (matches the registry key in `detectors/__init__.py`)
- [ ] Detail string includes which pattern category matched (e.g., "AWS access key ID", "GitHub token")

---

## 7. What This Does NOT Do

- **Does not scan tool responses.** MVP inspects outbound tool call arguments only. Response scanning is deferred to v1.
- **Does not redact or mask secrets.** Decision is binary allow/block. No `modify` action in v0.
- **Does not check environment variables.** Only scans the `arguments` dict of the `ToolCall`.
- **Does not do entropy-based detection.** No Shannon entropy calculation. Deterministic regex patterns only.
- **Does not cover all secret types.** Deliberately limited to the highest-value, lowest-false-positive patterns. Google Cloud keys, Azure keys, JWT tokens, etc. are v1 additions.

---

## 8. Risk

**Primary risk:** False positives on the `password=` pattern in normal text. A tool call with `{"query": "SELECT * FROM users WHERE password='reset'"}` contains `password=` followed by a value.

**Mitigation:** The regex requires `\s*[=:]\s*\S+` after the keyword. The SQL example above uses `='reset'` which *will* match. This is an acceptable trade-off — the SQL injection detector would independently catch the destructive SQL, and a `password=` pattern in a tool call argument is almost always a real credential being transmitted. If this causes benign-scenario failures, narrow the regex to require at least 8 chars after `=`/`:` — but don't do this preemptively.

**Secondary risk:** Regex performance on very long string values. Mitigated by the fact that all patterns use anchored or prefix-specific matching — no catastrophic backtracking possible.

---

## 9. Implementation Sequence

1. Copy `_extract_strings` from any existing detector (all four have identical implementations)
2. Define `_SECRET_PATTERNS` list with all 9 compiled regex/label pairs
3. Implement `detect()` — identical structure to `sql_injection.detect()`
4. Write all 17 tests
5. Run tests: `uv run pytest tests/test_detectors/test_secrets.py -v`
6. Confirm no ruff lint issues: `uv run ruff check src/agentgate/detectors/secrets.py tests/test_detectors/test_secrets.py`

Estimated time: 30–45 minutes. This is a mechanical detector with well-understood patterns.