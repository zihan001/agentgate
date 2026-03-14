# Issue #8: Implement param_rule Evaluation

**Status:** Spec ready · Implementation next  
**Parent:** PR2 — Policy Engine + Detectors + Audit  
**Depends on:** #4 (engine.py — ✅ done)  
**Blocks:** #15 (acceptance tests — AT-1, AT-2, AT-4 all exercise param_rule)  

---

## 1. What This Issue Delivers

A single function added to `engine.py` that evaluates `param_rule` policies as step 4 of the decision stack. When a tool call arrives and passes detectors + blocklist + allowlist, the engine iterates `param_rule` entries top-to-bottom. Each rule checks a specific parameter of the tool call against an operator/value condition. If the condition triggers (respecting `negate`), the call is blocked.

**No new files.** This is a surgical addition to `engine.py` plus unit tests.

---

## 2. Scope

### In scope

- Evaluate `param_rule` rules in `engine.py` between step 3 (tool_allow) and step 5 (chain_rule placeholder)
- Support all six operators: `equals`, `starts_with`, `ends_with`, `contains`, `matches` (regex), `in` (value-in-list)
- Support `negate: true` to invert the condition (block when condition is NOT met)
- Use pre-compiled regexes from `CompiledPolicy.regexes` for the `matches` operator
- Skip rule silently if the matched `param` does not exist in `tool_call.arguments`
- Support dot-notation param access for nested arguments (e.g., `options.recursive`)
- Top-to-bottom evaluation: first blocking param_rule wins

### Out of scope

- Wildcard tool matching (`match.tool: "*"`) — not needed for MVP acceptance tests; can be added later without breaking anything
- Type coercion (comparing non-string values) — all param values are treated as strings via `str()`
- Array-index access in param paths (e.g., `items[0].name`) — only dot-notation for dicts
- Any changes to `models.py`, `policy.py`, or `parser.py` — these already support `ParamRule` fully

---

## 3. Existing Code State

### `models.py` — already complete

```python
class ParamMatch(BaseModel):
    tool: str

class ParamCheck(BaseModel):
    param: str
    op: Literal["equals", "starts_with", "ends_with", "contains", "matches", "in"]
    value: str | list[str]
    negate: bool = False

class ParamRule(BaseModel):
    name: str
    type: Literal["param_rule"]
    match: ParamMatch
    check: ParamCheck
    message: str = ""
```

### `policy.py` — already compiles regexes

For `param_rule` with `op: matches`, regex is pre-compiled and stored at key `"{rule.name}:check.value"` in `CompiledPolicy.regexes`.

### `engine.py` — step 4 is a placeholder comment

```python
# --- Step 4: param_rule (Issue #8) ---
# Will iterate param_rules top-to-bottom here
```

---

## 4. Implementation Design

### 4.1 Param Resolution

Add a helper function to resolve a dotted param path against the tool call arguments dict:

```python
def _resolve_param(arguments: dict[str, Any], param_path: str) -> Any | _MISSING:
```

- Split `param_path` on `.` 
- Walk the dict, key by key
- If any key is missing or the intermediate value is not a dict, return a sentinel `_MISSING`
- Return the leaf value

**Why a sentinel instead of None:** The param value could legitimately be `None`. We need to distinguish "param not found" (skip rule) from "param is null" (evaluate rule).

### 4.2 Operator Evaluation

Add a function that takes the resolved param value, the operator, the check value, the negate flag, and the compiled regexes dict:

```python
def _eval_param_check(
    param_value: Any,
    check: ParamCheck,
    compiled_regexes: dict[str, re.Pattern],
    rule_name: str,
) -> bool:
```

Returns `True` if the rule should **block** (i.e., the condition matched and `negate=False`, or condition did not match and `negate=True`).

Operator logic (before negate is applied):

| Operator | `condition_met` when... |
|----------|------------------------|
| `equals` | `str(param_value) == check.value` |
| `starts_with` | `str(param_value).startswith(check.value)` |
| `ends_with` | `str(param_value).endswith(check.value)` |
| `contains` | `check.value in str(param_value)` |
| `matches` | `compiled_regex.search(str(param_value)) is not None` |
| `in` | `str(param_value) in check.value` (where `check.value` is a list) |

After computing `condition_met`:
- If `negate=False`: block when `condition_met` is `True`
- If `negate=True`: block when `condition_met` is `False`

Simplified: `should_block = condition_met != check.negate` — wait, that's wrong.

Let's be precise. The mental model from the spec:

> `negate: true` means "block if condition is NOT met"

So:
- `negate=False` → block if condition IS met (standard: "block emails matching external pattern")
- `negate=True` → block if condition is NOT met (inverted: "block if path does NOT start with /data/workspace/")

```python
should_block = condition_met if not check.negate else not condition_met
```

Or equivalently: `should_block = condition_met ^ check.negate` (XOR).

### 4.3 Engine Integration

In `engine.py`, after step 3 (tool_allow), insert:

```python
# --- Step 4: param_rule ---
param_rules = [r for r in rules if isinstance(r, ParamRule)]
for rule in param_rules:
    # Tool match check
    if rule.match.tool != "*" and rule.match.tool != tool_call.tool_name:
        continue
    
    # Resolve param
    value = _resolve_param(tool_call.arguments, rule.check.param)
    if value is _MISSING:
        continue  # skip silently per spec
    
    # Evaluate
    if _eval_param_check(value, rule.check, policy.regexes, rule.name):
        return Decision(
            action="block",
            matched_rule=rule.name,
            message=rule.message or f"Blocked by param_rule '{rule.name}'",
        )
```

### 4.4 Import Changes

Add to `engine.py` imports:

```python
import re
from typing import Any
from agentgate.models import Decision, ParamRule, ToolAllowRule, ToolBlockRule, ToolCall
```

---

## 5. Test Plan

All tests go in `tests/test_engine.py` (extend existing file) or a new `tests/test_param_rule.py` if the file gets too long. I recommend a new file since there are 20+ test cases.

### 5.1 Operator Tests (12 tests)

Each operator gets a positive match and a negative match:

| # | Test | Operator | Value | Param Value | Expected |
|---|------|----------|-------|-------------|----------|
| 1 | equals_match | `equals` | `"production"` | `"production"` | block |
| 2 | equals_no_match | `equals` | `"production"` | `"staging"` | allow |
| 3 | starts_with_match | `starts_with` | `"/data/"` | `"/data/file.txt"` | block |
| 4 | starts_with_no_match | `starts_with` | `"/data/"` | `"/etc/passwd"` | allow |
| 5 | ends_with_match | `ends_with` | `".exe"` | `"malware.exe"` | block |
| 6 | ends_with_no_match | `ends_with` | `".exe"` | `"report.csv"` | allow |
| 7 | contains_match | `contains` | `"password"` | `"my_password_123"` | block |
| 8 | contains_no_match | `contains` | `"password"` | `"normal text"` | allow |
| 9 | matches_match | `matches` | `".*@evil\\.com$"` | `"hacker@evil.com"` | block |
| 10 | matches_no_match | `matches` | `".*@evil\\.com$"` | `"user@safe.com"` | allow |
| 11 | in_match | `in` | `["delete", "drop"]` | `"delete"` | block |
| 12 | in_no_match | `in` | `["delete", "drop"]` | `"select"` | allow |

### 5.2 Negate Tests (4 tests)

| # | Test | Setup | Expected |
|---|------|-------|----------|
| 13 | negate_true_blocks_when_not_met | `starts_with "/data/"`, negate=True, path="/etc/passwd" | block (path does NOT start with /data/) |
| 14 | negate_true_allows_when_met | `starts_with "/data/"`, negate=True, path="/data/file.txt" | allow (path starts with /data/) |
| 15 | negate_false_blocks_when_met | `contains "DROP"`, negate=False, value="DROP TABLE" | block |
| 16 | negate_false_allows_when_not_met | `contains "DROP"`, negate=False, value="SELECT *" | allow |

### 5.3 Param Resolution Tests (4 tests)

| # | Test | Setup | Expected |
|---|------|-------|----------|
| 17 | missing_param_skips | check param `path`, tool call has no `path` key | allow (skip) |
| 18 | nested_param_dot_notation | check param `options.recursive`, args = `{"options": {"recursive": "true"}}` | evaluates against `"true"` |
| 19 | nested_param_missing_intermediate | check param `options.recursive`, args = `{"path": "/data"}` | allow (skip) |
| 20 | param_value_is_none | check param `path`, args = `{"path": None}` | evaluates against `"None"` (str coercion) |

### 5.4 Tool Match Tests (2 tests)

| # | Test | Setup | Expected |
|---|------|-------|----------|
| 21 | tool_matches_evaluates | rule matches tool `read_file`, call is `read_file` | evaluates rule |
| 22 | tool_mismatch_skips | rule matches tool `read_file`, call is `send_email` | skips rule, allow |

### 5.5 Integration / Precedence Tests (4 tests)

| # | Test | Setup | Expected |
|---|------|-------|----------|
| 23 | detector_beats_param_rule | secrets detector fires AND param_rule would also block | blocked by detector (step 1), not param_rule |
| 24 | blocklist_beats_param_rule | tool on blocklist AND param_rule applies | blocked by blocklist (step 2) |
| 25 | param_rule_first_match_wins | two param_rules both match, first has message "A", second has "B" | blocked with message "A" |
| 26 | param_rule_block_then_default_allow | param_rule blocks bad path; good path falls through to default allow | block for bad, allow for good |

### 5.6 Acceptance Test Coverage

These tests from `test_param_rule.py` directly support acceptance tests:

- **AT-1 (path traversal block):** Test 13 (negate + starts_with) — the canonical sandbox restriction
- **AT-4 (benign ops pass):** Tests 14, 26 — legitimate paths are allowed
- **AT-2 (credential exfil):** Covered by secrets detector, not param_rule — no overlap needed here

---

## 6. Implementation Checklist

```
[ ] Add _MISSING sentinel to engine.py
[ ] Add _resolve_param() to engine.py
[ ] Add _eval_param_check() to engine.py  
[ ] Wire step 4 into evaluate() between tool_allow and chain_rule placeholder
[ ] Add ParamRule to engine.py imports
[ ] Create tests/test_param_rule.py with 26 tests
[ ] Run full test suite (existing 120+ tests must still pass)
[ ] Run ruff check + ruff format
```

---

## 7. Edge Cases and Decisions

### Non-string param values

Tool call arguments can contain integers, booleans, or nulls. All operators coerce to string via `str()` before comparison. This means:
- `42` becomes `"42"` — `equals "42"` matches
- `True` becomes `"True"` — `contains "True"` matches
- `None` becomes `"None"` — `equals "None"` matches

This is intentional. The policy language operates on string patterns. If we need type-aware comparisons, that's a v1 feature.

### Empty string param

If `param_value` is `""`, all operators evaluate normally:
- `starts_with "/data/"` on `""` → `False`
- `contains ""` on any string → `True` (Python behavior)
- `matches ".*"` on `""` → `True`

No special-casing needed.

### Regex compilation failure

Already handled by `policy.py` at load time. If a regex in a `param_rule` doesn't compile, the proxy refuses to start. By the time `engine.py` runs, all regexes in `CompiledPolicy.regexes` are valid `re.Pattern` objects.

### Missing regex key in CompiledPolicy.regexes

Should not happen if `policy.py` works correctly. But defensively: if `_eval_param_check` can't find the compiled regex key, treat it as a non-match (don't crash the proxy). Log a warning.

### Wildcard tool match

The spec mentions `"*"` as a wildcard for `match.tool`. Include the `!= "*"` check in the implementation even though no acceptance test requires it — it's one line and the spec defines it.

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Dot-notation resolution bugs on deeply nested args | Low | Medium | Keep implementation simple (split + walk). Test with 2-level nesting only. Deeper nesting is a real-world edge case we don't need to gold-plate. |
| `str()` coercion surprises (e.g., dict becomes `"{'key': 'value'}"`) | Low | Low | Only leaf values should reach operators. If someone writes a param_rule targeting a dict-valued param, the string coercion gives them garbage — but that's a user error, not a bug. |
| Performance with many param_rules | Very low | Low | Linear scan is fine. Even 100 param_rules × 6 operators is <1ms. No optimization needed. |

---

## 9. What This Unblocks

- **Issue #15 (acceptance tests):** AT-1 (path traversal) and AT-4 (benign ops) both require `param_rule` with `starts_with` + `negate: true` for the sandboxed-files rule. AT-2 (email restriction) requires `param_rule` with `matches` + `negate: true`.
- **Issue #11 (chain detection):** Independent, but both feed into #15. These can be built in parallel.
- **Golden path demo policy:** The `agentgate.yaml.example` already includes two `param_rule` entries (sandboxed-files and internal-email-only). This issue makes them functional.