# Issue #22: Implement path_traversal Detector

**Status:** Implementation-ready  
**Milestone:** PR2 — Policy Engine + Detectors + Audit  
**Depends on:** None (standalone detector, uses existing `ToolCall` and `DetectorResult` models)  
**Blocks:** #26 (wire detectors into registry + engine), #15 (acceptance tests — AT-1 specifically)  
**Target file:** `src/agentgate/detectors/path_traversal.py`  
**Test file:** `tests/test_detectors/test_path_traversal.py`  
**Estimated effort:** 2–3 hours  
**Ref:** MVP Spec Section 3 (detector table), Section 6 AT-1 (path traversal block), Section 12 scenarios A1–A3/A13

---

## 1. Objective

Implement the `path_traversal` detector. This detector scans all string parameter values in a tool call for path traversal indicators: `../` sequences (including encoded variants), absolute paths targeting sensitive system directories, tilde-based home directory access, and null byte injection.

This detector is the most important for the golden path demo. AT-1 (the first acceptance test) requires it. It directly maps to OWASP ASI02 (Tool Misuse) and is exercised by 4 of the 15 adversarial evaluation scenarios (A1, A2, A3, A13).

---

## 2. Contract

```python
def detect(tool_call: ToolCall) -> DetectorResult
```

Same signature as `sql_injection.detect()`. Reuse the `_extract_strings()` helper pattern from `sql_injection.py` — recursively walk the arguments dict and extract all `(key_path, string_value)` pairs. Scan each string value against the pattern list. Return on first match.

**Return values:**
- `DetectorResult(matched=True, detector_name="path_traversal", detail="...")` — first pattern hit
- `DetectorResult(matched=False, detector_name="path_traversal")` — no patterns matched

---

## 3. Detection Patterns

Three categories of patterns, checked in order:

### 3.1 Traversal sequences

These catch explicit directory traversal attempts.

| Pattern | What it catches | Example |
|---------|----------------|---------|
| `../` literal | Basic relative traversal | `../../etc/passwd` |
| `..\` literal | Windows-style traversal | `..\..\windows\system32` |
| `%2e%2e%2f` / `%2e%2e/` | URL-encoded traversal | `%2e%2e%2fetc/passwd` |
| `%2e%2e%5c` | URL-encoded backslash variant | `%2e%2e%5cwindows` |

**Implementation:** Case-insensitive substring check. A single regex covering all four:

```
\.\./|\.\.\\|%2e%2e(%2f|/|%5c|\\)
```

Flags: `re.IGNORECASE`

### 3.2 Sensitive absolute paths

These catch direct access to known-sensitive system locations, regardless of whether traversal sequences are present.

| Pattern | What it catches |
|---------|----------------|
| `/etc/` | System config files (passwd, shadow, hosts) |
| `/root/` | Root home directory |
| `/proc/` | Process information (Linux) |
| `/sys/` | Kernel/device info (Linux) |
| `/var/log/` | System logs |
| `/dev/` | Device files |
| `~/.ssh/` or `~/.ssh` | SSH keys (any user) |
| `~/.aws/` or `~/.aws` | AWS credentials |
| `~/.gnupg/` or `~/.gnupg` | GPG keys |
| `~/.bashrc`, `~/.bash_history`, `~/.profile`, `~/.zshrc` | Shell configs/history |
| `/home/` followed by `/.ssh/` or `/.aws/` | Expanded tilde paths |

**Implementation:** Two regex patterns:

1. **Absolute sensitive dirs** — match at any position in the string (the path may be embedded in a longer argument):
   ```
   (?:^|/)(?:etc|root|proc|sys|dev)/|/var/log/
   ```
   But be careful: this must match `/etc/passwd` but NOT `/data/workspace/etc_report.csv`. The pattern needs a path separator before `etc`, `root`, etc. Use:
   ```
   (?:^|(?<=/))(?:etc|root|proc|sys|dev)/|(?:^|(?<=/))var/log/
   ```
   Actually, simpler approach — match these as substrings that look like path components:
   ```
   (?:^|/)etc/|(?:^|/)root/|(?:^|/)proc/|(?:^|/)sys/|(?:^|/)dev/|(?:^|/)var/log/
   ```

2. **Tilde paths** — home directory expansion:
   ```
   ~[^/]*?/\.(ssh|aws|gnupg)|~/\.(bashrc|bash_history|profile|zshrc|bash_profile)
   ```

3. **Expanded home paths** — `/home/<user>/.ssh/` etc:
   ```
   /home/[^/]+/\.(ssh|aws|gnupg)
   ```

### 3.3 Null byte injection

Null bytes in file paths can truncate path validation while the underlying OS processes the full path.

| Pattern | What it catches |
|---------|----------------|
| `%00` | URL-encoded null byte |
| `\x00` | Literal null byte (if somehow present in JSON string) |
| `\0` | C-style null representation |

**Implementation:** Substring check for `%00`, and also check for actual null bytes in the string (`\x00` character).

---

## 4. Design Decisions

### 4.1 No "allowed directory" configuration in the detector

The detector does NOT take an "allowed directory" parameter. It flags universally-dangerous paths (system dirs, SSH keys, traversal sequences). The policy's `param_rule` with `starts_with` handles project-specific sandboxing (e.g., "must start with `/data/workspace/`").

**Why:** Detectors are stateless, config-free pattern matchers. They run before policy rules. Mixing allowed-path logic into the detector would create a confusing overlap with `param_rule`. The separation is clean: detector catches known-bad patterns, `param_rule` enforces known-good boundaries.

### 4.2 Conservative on false positives

The biggest risk for this detector is flagging strings that contain path-like substrings in non-path contexts. Examples:
- A CSV cell containing `/etc/timezone` as data content
- A string like `"this is 3/4 of the report"` matching nothing (no `../`)
- A URL like `https://example.com/dev/docs` containing `/dev/`

**Mitigations:**
- `/dev/` pattern requires it to look like a filesystem path, not a URL path. Check that the string doesn't start with `http://` or `https://` before flagging `/dev/`, `/etc/`, etc. Actually — this gets complicated. Simpler: accept the false positive risk on `/dev/` in URLs and document it. The FPR target is ≤10%, and this edge case is unlikely in practice.
- Better mitigation: only flag these sensitive dirs when they appear at the **start** of the string value or immediately after a path separator that isn't part of a URL scheme. But this gets regex-heavy.

**Final decision:** Keep it simple. Flag `../` and `..\\` aggressively (these are almost never benign in tool call params). For sensitive absolute paths, require them to appear path-like: preceded by start-of-string, `/`, or whitespace. Accept that a string like `/data/workspace/etc/report.csv` will NOT be flagged (the `/etc/` is mid-path but preceded by a legitimate directory name — the regex `(?:^|/)etc/` would match this, which is wrong).

**Revised approach for sensitive dirs:** Match these patterns only when they appear as the **start of the string** or after `../` traversal. The purpose of the sensitive-dir patterns is to catch direct access like `path="/etc/passwd"` and traversals like `path="/data/workspace/../../../etc/passwd"`. If someone has a legitimate directory named `etc` inside their workspace, the `param_rule` sandbox check handles the boundary — not this detector.

Simplest correct implementation:

```python
_SENSITIVE_PATH_PREFIXES = [
    "/etc/", "/root/", "/proc/", "/sys/", "/dev/", "/var/log/",
    "~/.ssh", "~/.aws", "~/.gnupg",
    "~/.bashrc", "~/.bash_history", "~/.profile", "~/.zshrc", "~/.bash_profile",
]
```

Check: does the string **start with** any of these, OR does the string **contain** `../` (handled by category 3.1)?

For `/home/<user>/.ssh` style, use a regex: `^/home/[^/]+/\.(?:ssh|aws|gnupg)`.

This avoids the mid-path false positive problem entirely. If the path is `/data/workspace/etc/report.csv`, it doesn't start with `/etc/` so it passes. If it's `/etc/passwd`, it starts with `/etc/` so it's caught. If it's `../../etc/passwd`, the `../` pattern catches it first.

### 4.3 Reuse `_extract_strings` from sql_injection

Copy the `_extract_strings` helper. In Issue #26 (wire detectors), we can refactor it into a shared utility. For now, each detector is self-contained with its own copy — matches the existing `sql_injection.py` pattern.

---

## 5. Implementation Plan

### 5.1 `src/agentgate/detectors/path_traversal.py`

```python
"""Path traversal detector — flags ../ sequences, sensitive absolute paths, and null byte injection."""

from __future__ import annotations

import re
from typing import Any

from agentgate.models import DetectorResult, ToolCall


def _extract_strings(arguments: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Recursively extract all (key_path, string_value) pairs from arguments."""
    # Same implementation as sql_injection.py


# --- Pattern categories ---

# Category 1: Traversal sequences
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c|\\)", re.IGNORECASE)

# Category 2: Sensitive path prefixes (checked at start of string value)
_SENSITIVE_PREFIXES: list[str] = [
    "/etc/", "/root/", "/proc/", "/sys/", "/dev/", "/var/log/",
    "~/.ssh", "~/.aws", "~/.gnupg",
    "~/.bashrc", "~/.bash_history", "~/.profile", "~/.zshrc", "~/.bash_profile",
]

# Category 2b: /home/<user>/.<sensitive_dir> pattern
_HOME_SENSITIVE_RE = re.compile(r"^/home/[^/]+/\.(?:ssh|aws|gnupg)")

# Category 3: Null byte injection
_NULL_BYTE_RE = re.compile(r"%00|\\x00|\\0")


def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for path traversal indicators."""
    strings = _extract_strings(tool_call.arguments)

    for param_path, value in strings:
        # Category 1: Traversal sequences (../  ..\ and encoded variants)
        if _TRAVERSAL_RE.search(value):
            return DetectorResult(
                matched=True,
                detector_name="path_traversal",
                detail=f"Path traversal sequence in param '{param_path}'",
            )

        # Category 2: Sensitive absolute path prefixes
        for prefix in _SENSITIVE_PREFIXES:
            if value.startswith(prefix):
                return DetectorResult(
                    matched=True,
                    detector_name="path_traversal",
                    detail=f"Sensitive path prefix '{prefix}' in param '{param_path}'",
                )

        # Category 2b: /home/<user>/.ssh etc
        if _HOME_SENSITIVE_RE.search(value):
            return DetectorResult(
                matched=True,
                detector_name="path_traversal",
                detail=f"Sensitive home directory path in param '{param_path}'",
            )

        # Category 3: Null byte injection
        if _NULL_BYTE_RE.search(value) or "\x00" in value:
            return DetectorResult(
                matched=True,
                detector_name="path_traversal",
                detail=f"Null byte injection in param '{param_path}'",
            )

    return DetectorResult(matched=False, detector_name="path_traversal")
```

**Key implementation notes:**
- `_SENSITIVE_PREFIXES` uses `str.startswith()`, not regex — faster and clearer
- `_TRAVERSAL_RE` catches `../`, `..\`, `%2e%2e/`, `%2e%2e%2f`, `%2e%2e\`, `%2e%2e%5c`
- `_NULL_BYTE_RE` catches encoded null bytes; `"\x00" in value` catches literal null bytes
- Return on first match (same as sql_injection — fail-fast)

---

## 6. Test Plan

### 6.1 Test file: `tests/test_detectors/test_path_traversal.py`

All tests are **sync, no I/O** — they construct `ToolCall` objects directly and call `detect()`.

### 6.2 Positive cases (must match — 8 tests)

| # | Test name | Tool call | Why it should match |
|---|-----------|-----------|-------------------|
| P1 | `test_relative_traversal_etc_passwd` | `read_file(path="../../etc/passwd")` | Classic `../` traversal |
| P2 | `test_absolute_etc_shadow` | `read_file(path="/etc/shadow")` | Direct sensitive path access |
| P3 | `test_tilde_ssh_key` | `read_file(path="~/.ssh/id_rsa")` | SSH key access via tilde |
| P4 | `test_traversal_from_allowed_dir` | `read_file(path="/data/workspace/../../../etc/passwd")` | Traversal that starts in allowed dir then escapes |
| P5 | `test_proc_self_environ` | `read_file(path="/proc/self/environ")` | Process environment leak |
| P6 | `test_url_encoded_traversal` | `read_file(path="%2e%2e%2f%2e%2e%2fetc/passwd")` | Encoded `../` bypass attempt |
| P7 | `test_null_byte_injection` | `read_file(path="/data/workspace/safe%00../../etc/passwd")` | Null byte truncation trick |
| P8 | `test_home_user_ssh` | `read_file(path="/home/ubuntu/.ssh/authorized_keys")` | Expanded home dir SSH access |

### 6.3 Negative cases (must NOT match — 7 tests)

| # | Test name | Tool call | Why it should pass |
|---|-----------|-----------|-------------------|
| N1 | `test_safe_absolute_path` | `read_file(path="/data/workspace/reports/q4.csv")` | Normal file in allowed dir |
| N2 | `test_safe_relative_path` | `read_file(path="./local_file.txt")` | Benign relative path |
| N3 | `test_dotdot_in_non_path_string` | `send_email(body="revenue grew 3/4 vs ../last quarter")` | `../` appears in natural language but this is a non-path string — **wait, this WILL match**. See decision below. |
| N4 | `test_safe_nested_dir` | `read_file(path="/data/workspace/etc/report.csv")` | Dir named `etc` inside workspace — not `/etc/` |
| N5 | `test_no_string_params` | `list_directory(recursive=true, depth=3)` | No string params to scan |
| N6 | `test_empty_arguments` | `read_file()` (empty args) | No arguments at all |
| N7 | `test_safe_absolute_path_deep` | `read_file(path="/data/workspace/subdir/another/file.md")` | Deep but safe path |

### 6.4 N3 decision: `../` in non-path strings

The detector scans **all** string params, not just ones named `path`. This means `send_email(body="see ../last quarter")` WILL trigger the `../` pattern.

**Accept this.** Here's why:
- The detector is intentionally aggressive on `../` — it's a traversal indicator regardless of context
- In practice, `../` appearing in email bodies or non-path params is rare
- The cost of a false negative (missing a traversal) is much higher than a false positive (blocking a weird email body)
- If this becomes a real FPR problem, v1 can add a heuristic: only flag `../` if the string looks path-like (contains `/` or `\` as path separators beyond the `../` itself)

**Revised N3:** Change the negative test to something that genuinely won't match:

| N3 | `test_slash_in_non_traversal_context` | `send_email(body="profits grew quarter/quarter")` | Forward slash but no `../` pattern |

### 6.5 Edge cases (2 tests)

| # | Test name | Tool call | Expected |
|---|-----------|-----------|----------|
| E1 | `test_nested_arg_traversal` | `write_file(options={"backup_path": "../../tmp/backup"})` | Match — traversal in nested dict |
| E2 | `test_windows_backslash_traversal` | `read_file(path="..\\..\\windows\\system32\\config\\sam")` | Match — Windows-style traversal |

### 6.6 Test count: 17 total (8 positive + 7 negative + 2 edge)

This follows the `sql_injection` pattern (16 tests: 7 positive + 7 negative + 2 edge) but slightly larger because path traversal has more pattern categories.

---

## 7. Acceptance Test Mapping

This detector is required by **AT-1** from the spec:

> **AT-1: Path Traversal Block**  
> Agent calls `read_file(path="/etc/passwd")` with a policy that restricts filesystem access to `/data/workspace/`.  
> Expected: Call is blocked. Audit log records with `matched_detector: path_traversal`.

AT-1 requires both the detector AND a `param_rule`. The detector catches `/etc/passwd` via the sensitive prefix check. The `param_rule` (Issue #8) would also catch it via `starts_with /data/workspace/ + negate`. Defense in depth — both should fire, but detectors run first (step 1 in the decision stack) and short-circuit.

This detector also covers adversarial eval scenarios A1, A2, A3, A13:
- A1: `read_file(path="/etc/passwd")` — sensitive prefix
- A2: `read_file(path="../../.ssh/id_rsa")` — traversal + tilde-like
- A3: `read_file(path="/data/workspace/../../../etc/shadow")` — traversal
- A13: `read_file(path="/data/workspace/~/.bashrc")` — this is a weird one; it's not actually a tilde expansion since it's mid-path. The `~/.bashrc` prefix check won't fire because the string doesn't start with `~/`. This scenario may need to be re-evaluated at eval time — it might rely on `param_rule` rather than the detector.

---

## 8. Risk: False Positives

**Primary FPR concern:** `../` in non-path string parameters (email bodies, descriptions, notes).

**Likelihood:** Low in practice. Tool call arguments are typically structured — path params contain paths, email params contain email content. Natural language rarely contains `../`.

**Mitigation if FPR becomes a problem (v1):**
- Add a path-likeness heuristic: only flag `../` if the string also contains `/` or `\` as path separators (beyond the `../` itself)
- Or: allow detectors to be scoped to specific param names in the policy config

**For MVP:** Ship the aggressive version. Measure FPR in the evaluation suite (10 benign scenarios). If FPR > 0 on the benign suite, tighten the patterns before merge.

---

## 9. What This Does NOT Cover

- **Symlink traversal** — requires filesystem access, not static analysis
- **Path canonicalization** — we don't resolve `./`, `//`, or symlinks. We flag the patterns.
- **Allowed directory enforcement** — that's `param_rule` (Issue #8), not this detector
- **Response scanning** — checking if a tool's response contains file contents from sensitive paths (deferred to v1)
- **Unicode/punycode path tricks** — v1 enhancement

---

## 10. Files Changed

| File | Action | What |
|------|--------|------|
| `src/agentgate/detectors/path_traversal.py` | Rewrite from stub | Full detector implementation |
| `tests/test_detectors/test_path_traversal.py` | Create new | 17 tests |

No changes to any other files. The detector is self-contained. Wiring into the engine happens in Issue #26.

---

## 11. Definition of Done

- [ ] `detect(tool_call)` returns `DetectorResult(matched=True, detector_name="path_traversal", detail=...)` for all traversal, sensitive path, and null byte patterns
- [ ] `detect(tool_call)` returns `DetectorResult(matched=False, detector_name="path_traversal")` for safe paths
- [ ] Recursive string extraction handles nested dicts and lists (same as sql_injection)
- [ ] 8 positive tests pass (traversal, absolute sensitive, tilde, encoded, null byte, home dir)
- [ ] 7 negative tests pass (safe paths, non-path strings, no-string params, empty args)
- [ ] 2 edge case tests pass (nested args, Windows backslash)
- [ ] All 17 tests are sync, no I/O, no fixtures beyond `ToolCall` construction
- [ ] All existing tests still pass (72 total: 11 models + 12 parser + 10 policy + 10 engine + 5 proxy + 8 proxy_policy + 16 sql_injection)
- [ ] Zero benign test suite false positives (manually verify B1, B2, B3, B6, B8, B9 from eval plan pass through this detector)