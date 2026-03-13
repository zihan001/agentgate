# Issue #21: Implement SQL Injection Detector

**Status:** Implementation-ready  
**Milestone:** PR2 — Policy Engine + Detectors + Audit  
**Depends on:** Nothing (parallel with #22–#25; uses only `models.py`)  
**Blocks:** #26 (wire detectors into engine)  
**Target file:** `src/agentgate/detectors/sql_injection.py`  
**Test file:** `tests/test_detectors/test_sql_injection.py`  
**Estimated effort:** 1.5–2 hours  
**Ref:** MVP Spec Section 3 (Minimum rule/detector types), Section 11 Risk 2 (false positives), Section 12 A5

---

## 1. Objective

Implement a SQL injection detector that scans all string-typed values in a tool call's `arguments` dict for destructive SQL patterns. The detector must catch real injection payloads (DROP, DELETE, TRUNCATE, UNION SELECT, tautology attacks) while producing zero false positives on benign content that happens to contain SQL-like words (e.g., `"SELECT committee"`, `"drop the meeting notes"`, `"The DELETE key is broken"`).

The detector is a pure function. `ToolCall` in, `DetectorResult` out. No I/O, no async, no state, no side effects. It runs in the detector pipeline before the rule engine, and a match short-circuits to `block`.

---

## 2. Scope

### In scope

- `detect(tool_call: ToolCall) -> DetectorResult` function in `src/agentgate/detectors/sql_injection.py`
- Recursive scan of all string values in `tool_call.arguments` (including nested dicts/lists)
- Detection of destructive SQL patterns only (see Section 4)
- Case-insensitive matching
- 7 positive test cases, 7 negative test cases (exceeds the 5+/5+ minimum)

### Out of scope

- Read-only SQL injection (`SELECT`-only without destructive combinations) — v1 enhancement
- Encoded/obfuscated SQL (hex encoding, Unicode normalization tricks, comment-based evasion `/**/`) — v1 enhancement
- Detection in non-string parameter values (integers, booleans) — not meaningful for SQL injection
- Wiring the detector into the engine pipeline (Issue #26)
- Any I/O, async, or state

---

## 3. Technical Decisions

### Decision 1: Scan all string values recursively, not just top-level params

**Choice:** Walk `tool_call.arguments` recursively. For every value that is a `str`, run the pattern check. For dicts, recurse into values. For lists, recurse into elements. Ignore non-string leaf values.

**Rationale:** Tool call arguments can be nested. A tool might accept `{"query": {"sql": "DROP TABLE users"}}` or `{"commands": ["DROP TABLE users"]}`. Scanning only top-level string values would miss these. The recursion adds ~5 lines and eliminates a class of bypasses.

### Decision 2: Two-tier detection — destructive keywords + injection indicators

**Choice:** The detector uses two independent detection tiers. A match on EITHER tier triggers detection.

- **Tier 1 — Destructive statements:** Standalone destructive SQL keywords/phrases in a context that looks like SQL (word-boundary-delimited, with structural SQL syntax nearby).
- **Tier 2 — Classic injection indicators:** Patterns that are unambiguous injection artifacts regardless of destructive keywords (tautologies, comment terminators, stacked queries with semicolons).

**Rationale:** Tier 1 catches `DROP TABLE users`, `DELETE FROM accounts`, `TRUNCATE TABLE sessions`. Tier 2 catches `' OR 1=1 --`, `'; --`, `UNION SELECT password FROM users`. Together they cover the OWASP SQL injection top patterns without flagging benign English text.

### Decision 3: Word-boundary matching to avoid false positives on English prose

**Choice:** All regex patterns use word boundaries (`\b`) to avoid matching SQL keywords embedded in English words or sentences.

**Rationale:** `"The SELECT committee met on Tuesday"` contains "SELECT" but is not SQL. `"Please drop the meeting notes in the folder"` contains "drop" but is not SQL. Word boundaries alone are necessary but not sufficient — we also require structural SQL context (see patterns below). The combination of word boundaries + SQL structural context eliminates false positives from natural language.

### Decision 4: Case-insensitive matching with `re.IGNORECASE`

**Choice:** All patterns are compiled with `re.IGNORECASE`.

**Rationale:** SQL keywords are case-insensitive. Attackers commonly mix case (`DrOp TaBlE`) to evade naive detectors. Case-insensitive matching catches this with zero additional complexity.

### Decision 5: Return the first matching pattern's detail, not all matches

**Choice:** On first match, return `DetectorResult(matched=True, detector_name="sql_injection", detail="...")` immediately. Don't scan remaining patterns.

**Rationale:** The detector pipeline short-circuits on any detector match. There's no benefit to finding all matches — one is enough to block. Early return is faster and simpler.

### Decision 6: No dependency beyond `models.py` and stdlib `re`

**Choice:** `sql_injection.py` imports only `ToolCall`, `DetectorResult` from `models.py` and `re` from stdlib.

**Rationale:** Leaf module. Same pattern as every other detector. No circular dependencies.

---

## 4. Detection Patterns

### Tier 1 — Destructive SQL Statements

These patterns detect SQL statements that modify or destroy data. Each requires the destructive keyword in a structural SQL context to avoid false positives on English prose.

| Pattern | What it catches | Example |
|---------|----------------|---------|
| `DROP\s+(TABLE\|DATABASE\|INDEX\|VIEW\|SCHEMA)` | Schema/object destruction | `DROP TABLE users` |
| `DELETE\s+FROM` | Row deletion | `DELETE FROM accounts WHERE 1=1` |
| `TRUNCATE\s+(TABLE)?` | Table truncation | `TRUNCATE TABLE sessions` |
| `ALTER\s+TABLE` | Schema modification | `ALTER TABLE users DROP COLUMN password` |
| `UPDATE\s+\S+\s+SET` | Row modification (requires SET) | `UPDATE users SET role='admin'` |
| `INSERT\s+INTO` | Data injection | `INSERT INTO admins VALUES ('attacker', 'password')` |
| `EXEC(\|UTE)\s*\(` | Stored procedure execution | `EXEC('DROP TABLE users')` |

Implementation note: Each pattern is a `re.compile(r"\b<pattern>\b", re.IGNORECASE)`. The `\b` word boundaries prevent matching inside words. The structural context (e.g., `DROP` must be followed by `TABLE`/`DATABASE`/etc.) prevents matching "drop" in natural language.

### Tier 2 — Injection Indicators

These patterns detect artifacts that are strong signals of SQL injection, independent of destructive keywords.

| Pattern | What it catches | Example |
|---------|----------------|---------|
| `UNION\s+(ALL\s+)?SELECT` | Union-based data extraction | `UNION SELECT password FROM users` |
| `OR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?` | Tautology injection | `OR 1=1`, `OR '1'='1'` |
| `;\s*--` | Stacked query with comment terminator | `'; --` |
| `;\s*(DROP\|DELETE\|INSERT\|UPDATE\|TRUNCATE\|ALTER\|EXEC)` | Stacked query with destructive follow-up | `'; DROP TABLE users` |

Implementation note: The tautology pattern is intentionally narrow — it matches `OR <digit>=<digit>` with optional quotes. This catches the canonical `OR 1=1` and variants like `OR '1'='1'` without flagging legitimate uses of `OR` in English text.

### What is NOT detected (explicit false-negative acceptance)

| Pattern | Why not detected | Planned |
|---------|-----------------|---------|
| `SELECT * FROM users` (read-only) | Not destructive. Flagging SELECT statements would cause false positives on agents that legitimately query databases. | v1: optional strict mode |
| `/**/` comment evasion (`DR/**/OP TABLE`) | Adds regex complexity. Evasion sophistication beyond MVP. | v1 |
| Hex/Unicode encoding (`0x44524F50`) | Requires decoding layer. Out of scope for regex detector. | v1: pre-processing layer |
| `WAITFOR DELAY` / time-based blind injection | Not destructive. Low priority for tool-call context. | v1 |
| `INTO OUTFILE` / `LOAD_FILE` | File-based SQL injection. Uncommon in tool-call context. | v1 |

---

## 5. Implementation

### `_extract_strings(arguments: dict) -> list[tuple[str, str]]`

```
def _extract_strings(arguments: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    """Recursively extract all (key_path, string_value) pairs from arguments."""
    results = []
    for key, value in arguments.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, str):
            results.append((path, value))
        elif isinstance(value, dict):
            results.extend(_extract_strings(value, path))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                item_path = f"{path}[{i}]"
                if isinstance(item, str):
                    results.append((item_path, item))
                elif isinstance(item, dict):
                    results.extend(_extract_strings(item, item_path))
    return results
```

This is ~15 lines. It returns the key path for use in the `detail` message (e.g., `"SQL injection detected in param 'query': matched 'DROP TABLE'"`).

### `_SQL_PATTERNS: list[tuple[re.Pattern, str]]`

A module-level list of `(compiled_pattern, human_readable_label)` tuples. Compiled once at import time. The label is used in `DetectorResult.detail`.

```python
_SQL_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Tier 1: Destructive statements
    (re.compile(r"\bDROP\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b", re.I), "DROP statement"),
    (re.compile(r"\bDELETE\s+FROM\b", re.I), "DELETE FROM statement"),
    (re.compile(r"\bTRUNCATE\s+(TABLE\s+)?\b\w", re.I), "TRUNCATE statement"),
    (re.compile(r"\bALTER\s+TABLE\b", re.I), "ALTER TABLE statement"),
    (re.compile(r"\bUPDATE\s+\S+\s+SET\b", re.I), "UPDATE...SET statement"),
    (re.compile(r"\bINSERT\s+INTO\b", re.I), "INSERT INTO statement"),
    (re.compile(r"\bEXEC(UTE)?\s*\(", re.I), "EXEC/EXECUTE call"),
    # Tier 2: Injection indicators
    (re.compile(r"\bUNION\s+(ALL\s+)?SELECT\b", re.I), "UNION SELECT"),
    (re.compile(r"\bOR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", re.I), "OR tautology"),
    (re.compile(r";\s*--", re.I), "stacked query with comment"),
    (re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|TRUNCATE|ALTER|EXEC)\b", re.I), "stacked destructive query"),
]
```

### `detect(tool_call: ToolCall) -> DetectorResult`

```
def detect(tool_call: ToolCall) -> DetectorResult:
    """Scan all string parameter values for SQL injection patterns.

    Returns DetectorResult with matched=True on first pattern hit.
    """
    strings = _extract_strings(tool_call.arguments)

    for param_path, value in strings:
        for pattern, label in _SQL_PATTERNS:
            if pattern.search(value):
                return DetectorResult(
                    matched=True,
                    detector_name="sql_injection",
                    detail=f"SQL injection detected in param '{param_path}': {label}",
                )

    return DetectorResult(matched=False, detector_name="sql_injection")
```

This is ~10 lines. The full module is ~60 lines including imports, patterns, and the helper.

---

## 6. Test Plan

**File:** `tests/test_detectors/test_sql_injection.py`

All tests are synchronous. No fixtures, no subprocess, no I/O. Pure function testing.

### Helper

```python
def _call(arguments: dict) -> ToolCall:
    """Build a ToolCall with the given arguments."""
    return ToolCall(tool_name="query_db", arguments=arguments, call_id=1)
```

### Positive Cases (7) — Must Detect

| # | Test name | Input | Pattern matched |
|---|-----------|-------|-----------------|
| P1 | `test_drop_table` | `{"query": "DROP TABLE users"}` | DROP statement |
| P2 | `test_delete_from` | `{"query": "'; DELETE FROM accounts; --"}` | DELETE FROM + stacked query |
| P3 | `test_union_select` | `{"query": "' UNION SELECT password FROM users --"}` | UNION SELECT |
| P4 | `test_or_tautology` | `{"query": "' OR 1=1 --"}` | OR tautology |
| P5 | `test_update_set` | `{"query": "UPDATE users SET role='admin' WHERE id=1"}` | UPDATE...SET |
| P6 | `test_truncate_table` | `{"query": "TRUNCATE TABLE sessions"}` | TRUNCATE statement |
| P7 | `test_nested_param_injection` | `{"config": {"sql": "DROP TABLE logs"}}` | DROP statement (nested) |

For each: assert `result.matched is True`, `result.detector_name == "sql_injection"`, `result.detail` contains the pattern label.

### Negative Cases (7) — Must NOT Detect

| # | Test name | Input | Why it's benign |
|---|-----------|-------|-----------------|
| N1 | `test_benign_select` | `{"query": "SELECT * FROM sales WHERE quarter = 'Q4'"}` | Read-only SELECT, not destructive |
| N2 | `test_english_prose_select` | `{"text": "The SELECT committee met on Tuesday"}` | English prose containing SQL keyword |
| N3 | `test_english_prose_drop` | `{"text": "Please drop the meeting notes in the shared folder"}` | "drop" in natural language context |
| N4 | `test_normal_string_params` | `{"name": "John", "email": "john@example.com"}` | No SQL at all |
| N5 | `test_empty_arguments` | `{}` | Empty arguments |
| N6 | `test_numeric_params_ignored` | `{"count": 42, "active": True, "path": "/data/file.txt"}` | Non-string values skipped, string has no SQL |
| N7 | `test_benign_insert_english` | `{"text": "Insert the new section after paragraph 3"}` | "Insert" in natural language, no `INTO` follows |

For each: assert `result.matched is False`, `result.detector_name == "sql_injection"`.

### Edge Case Tests (2 additional)

| # | Test name | Input | Expected |
|---|-----------|-------|----------|
| E1 | `test_case_insensitive` | `{"query": "dRoP tAbLe users"}` | `matched=True` — mixed case evasion caught |
| E2 | `test_list_param_scanning` | `{"queries": ["SELECT 1", "DROP TABLE x"]}` | `matched=True` — second list element caught |

---

## 7. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | All 7 destructive SQL patterns (DROP, DELETE FROM, TRUNCATE, ALTER TABLE, UPDATE...SET, INSERT INTO, EXEC) are detected | Tests P1–P6, E1 |
| AC-2 | All 4 injection indicators (UNION SELECT, OR tautology, stacked + comment, stacked + destructive) are detected | Tests P2–P4 |
| AC-3 | Benign SELECT statements are NOT flagged | Test N1 |
| AC-4 | English prose containing SQL-like words is NOT flagged | Tests N2, N3, N7 |
| AC-5 | Nested dict and list argument values are scanned | Tests P7, E2 |
| AC-6 | `DetectorResult.detail` includes the param path and pattern label | All positive tests |
| AC-7 | Zero false positives on all 7 negative cases | Tests N1–N7 |

---

## 8. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **False positive on `INSERT INTO` in English** (e.g., "insert into the discussion") | Low | Medium | The pattern requires `INSERT\s+INTO` — two words together with SQL-structural context. "Insert into" in English is uncommon as a direct two-word phrase with a noun following immediately. If a false positive surfaces in evaluation, narrow to `INSERT\s+INTO\s+\w+\s*\(` (requiring parentheses). |
| **Regex ReDoS on crafted input** | Very Low | Low | All patterns use `\s+` (not `\s*` in sensitive positions) and have bounded alternation. No nested quantifiers. Not a real risk for the pattern set. |
| **Attacker uses comment evasion (`DR/**/OP`)** | Medium | Low (for MVP) | Accepted false negative. Documented in Section 4. v1 will add a comment-stripping pre-processor. |
| **Attacker uses encoding (`0x44524F50`)** | Medium | Low (for MVP) | Accepted false negative. Documented in Section 4. v1 will add a hex/unicode decoding pre-processor. |
| **UPDATE without SET context** ("Please update your records") | Low | Low | Pattern requires `UPDATE\s+\S+\s+SET` — the SET keyword after a table name. "Update your records" won't match because there's no SET following. |

---

## 9. How This Integrates with the Detector Pipeline (Issue #26 Preview)

The detector registry in `detectors/__init__.py` maps `"sql_injection"` to `"agentgate.detectors.sql_injection"`. Issue #26 will:

1. Import the `detect` function from each enabled detector module
2. Call `detect(tool_call)` for each enabled detector
3. If any returns `matched=True`, short-circuit to `Decision(action="block", matched_detector=result.detector_name, message=result.detail)`
4. Detectors run before all policy rules (step 1 in the decision stack)

The `detect` function signature — `detect(tool_call: ToolCall) -> DetectorResult` — is the contract. All 5 non-chain detectors (#21–#25) use this exact same signature.

---

## 10. Design Constraints for Downstream Issues

1. **`detect()` signature is the contract.** All detectors export `detect(tool_call: ToolCall) -> DetectorResult`. Issue #26 depends on this. Do not deviate.

2. **`_extract_strings()` should be shared.** Issues #22 (path traversal), #23 (command injection), and #25 (secrets) all need to scan string values in arguments. Extract `_extract_strings` into a shared utility in `detectors/__init__.py` or a `detectors/_utils.py` module. For this issue, implement it locally. Issue #26 can refactor to shared when wiring all detectors together.

3. **Patterns are compiled at import time.** Module-level `re.compile()` ensures zero regex compilation at detection time. The engine calls `detect()` on every `tools/call` request — regex compilation per call would add measurable latency.

4. **`detector_name` must match the config key.** `DetectorResult.detector_name == "sql_injection"` must match the key in `DetectorsConfig` and the `REGISTRY` dict in `detectors/__init__.py`. This is how the engine maps a detector match back to the config toggle.

---

## 11. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/detectors/sql_injection.py` | **Replace stub** | `_extract_strings()`, `_SQL_PATTERNS`, `detect()` |
| `tests/test_detectors/test_sql_injection.py` | **Replace stub** | 16 tests (7 positive + 7 negative + 2 edge cases) |

No other files are touched. `models.py`, `engine.py`, `proxy.py`, `detectors/__init__.py` are unchanged by this issue.

---

## 12. Definition of Done

- [ ] `src/agentgate/detectors/sql_injection.py` contains `detect(tool_call: ToolCall) -> DetectorResult`
- [ ] All 7 Tier 1 destructive SQL patterns detected (DROP, DELETE FROM, TRUNCATE, ALTER TABLE, UPDATE...SET, INSERT INTO, EXEC)
- [ ] All 4 Tier 2 injection indicators detected (UNION SELECT, OR tautology, stacked + comment, stacked + destructive)
- [ ] Benign SELECT statements NOT flagged
- [ ] English prose with SQL-like words NOT flagged
- [ ] Nested dict and list argument values scanned recursively
- [ ] Case-insensitive matching (mixed-case evasion caught)
- [ ] `DetectorResult.detail` includes param path and matched pattern label
- [ ] `tests/test_detectors/test_sql_injection.py` contains 16 tests, all passing
- [ ] Zero false positives on all negative test cases
- [ ] No async code — pure synchronous function
- [ ] No dependency beyond `models.py` and stdlib `re`
- [ ] All existing tests (69 from PR1) still pass
- [ ] All tests run in under 1 second (pure functions, no I/O)