# Issue #3: Implement YAML Policy Loader

**Status:** Implementation-ready  
**Milestone:** PR1 — First End-to-End Interception  
**Depends on:** Nothing (parallel with #1, #2)  
**Blocks:** #4 (rule engine), #5 (end-to-end wiring)  
**Target file:** `src/agentgate/policy.py`  
**Test file:** `tests/test_policy.py`  
**Estimated effort:** 2–3 hours  
**Ref:** MVP Spec Section 5 (Policy Language v0), Section 8 (Policy Loader component)

---

## 1. Objective

Load `agentgate.yaml` from disk, parse it with PyYAML, validate it against the `PolicyConfig` Pydantic model, pre-compile all regex patterns found in `param_rule` and `chain_rule` definitions, and return a fully validated, ready-to-evaluate `PolicyConfig` instance. Reject malformed input with clear, actionable error messages that tell the developer exactly what is wrong and where.

This is a pure function. File path in, typed config out (or a clear error). No async, no I/O beyond the initial file read, no side effects. The engine (#4) consumes the output of this module — the loader's job is to guarantee that by the time the engine sees a `PolicyConfig`, every field is valid, every regex compiles, and every rule is structurally correct.

---

## 2. Scope

### In scope

- `load_policy(path: str | Path) -> PolicyConfig` function in `src/agentgate/policy.py`
- `compile_regexes(config: PolicyConfig) -> CompiledPolicy` function
- `CompiledPolicy` dataclass holding the validated config + pre-compiled regex map
- All error cases from MVP Spec Section 5 (Error Handling)
- 10 unit tests covering valid loading, all error categories, and regex compilation

### Out of scope

- Rule evaluation logic (Issue #4)
- Policy hot-reload / SIGHUP (v1)
- Environment variable substitution in values (v1)
- Multiple policy files or includes (v1)
- Schema migration between policy versions
- `agentgate init` command (Issue #14 — just copies the example file)

---

## 3. Technical Decisions

### Decision 1: Two-phase loading — parse then compile

**Choice:** Separate `load_policy()` (YAML → Pydantic) from `compile_regexes()` (Pydantic → CompiledPolicy with compiled `re.Pattern` objects).

**Rationale:** Pydantic validates structure. Regex compilation validates pattern correctness. These are distinct failure modes with different error messages. Keeping them separate means: (a) `load_policy` tests don't need regex fixtures, (b) `compile_regexes` can be tested with programmatically-built `PolicyConfig` objects, (c) the engine receives `CompiledPolicy` with pre-compiled patterns — zero regex compilation at evaluation time.

### Decision 2: `CompiledPolicy` is a dataclass, not a Pydantic model

**Choice:** Plain `@dataclass` holding `config: PolicyConfig` and `regexes: dict[str, re.Pattern]`.

**Rationale:** `CompiledPolicy` is an internal runtime object, not a serialization boundary. `re.Pattern` objects are not JSON-serializable, and Pydantic v2's `arbitrary_types_allowed` adds unnecessary complexity for an object that never crosses a serialization boundary. A dataclass is simpler and sufficient.

### Decision 3: Fail-fast on startup, not at evaluation time

**Choice:** `load_policy()` and `compile_regexes()` raise `PolicyLoadError` (a custom exception). The proxy catches this at startup and exits with a clear message. No partial loading, no fallback to defaults.

**Rationale:** A malformed policy is a configuration error that must be fixed before the proxy runs. Silent fallback to a default policy would mask configuration bugs and create a false sense of security. The developer must see the error, fix the YAML, and restart.

### Decision 4: Error messages include file path and context

**Choice:** Every error message includes: what went wrong, which field or rule caused it, and what the developer should do to fix it.

**Rationale:** "Validation error" is useless. "Policy rule 'sandboxed-files' (param_rule): regex in check.value failed to compile: unbalanced parenthesis at position 12" is actionable. Since we're using Pydantic for structural validation, most errors come for free — we just need to format them well. Regex errors are the ones we must handle manually.

### Decision 5: Regex key scheme for the compiled pattern map

**Choice:** The `regexes` dict in `CompiledPolicy` uses keys of the form `{rule_name}:{field_path}` — e.g., `"sandboxed-files:check.value"`, `"block-exfil:steps.0.output_matches"`, `"block-exfil:steps.1.param_matches.to"`.

**Rationale:** The engine needs to look up the compiled pattern for a specific rule's specific field. A flat dict with deterministic keys is the simplest lookup structure. The key format is human-readable for debugging.

### Decision 6: No dependency on `proxy.py` or `parser.py`

**Choice:** `policy.py` imports only from `models.py`, stdlib (`pathlib`, `re`, `yaml`), and defines its own `PolicyLoadError`.

**Rationale:** Leaf module. No circular dependencies. The proxy depends on policy, never the reverse.

---

## 4. Data Model

### `PolicyLoadError`

```python
class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded, parsed, or validated."""
    pass
```

Single exception type. The message carries all context. No error codes, no error hierarchy — overkill for a startup config loader.

### `CompiledPolicy`

```python
@dataclass(frozen=True)
class CompiledPolicy:
    """A fully validated and compiled policy, ready for the rule engine."""
    config: PolicyConfig
    regexes: dict[str, re.Pattern]
```

`frozen=True` because the compiled policy is immutable after loading. The engine reads it, never modifies it.

### Where regexes come from

Regexes appear in exactly three places in the policy language:

| Rule type | Field | When it contains a regex |
|-----------|-------|--------------------------|
| `param_rule` | `check.value` | When `check.op == "matches"` |
| `chain_rule` | `steps[i].output_matches` | Always (if present) |
| `chain_rule` | `steps[i].param_matches[key]` | Always (values are regex patterns) |

All other `param_rule` operators (`equals`, `starts_with`, `ends_with`, `contains`, `in`) use literal string comparison — no regex compilation needed.

---

## 5. Implementation

### `load_policy(path: str | Path) -> PolicyConfig`

```
1. Convert path to Path object
2. If file doesn't exist → raise PolicyLoadError(f"Policy file not found: {path}")
3. Read file contents as UTF-8
4. Try yaml.safe_load(contents)
   - On yaml.YAMLError → raise PolicyLoadError with YAML error details
     (PyYAML includes line/column in its exception message — forward it)
5. If result is None → raise PolicyLoadError("Policy file is empty")
6. If result is not a dict → raise PolicyLoadError("Policy file must be a YAML mapping, got {type}")
7. Try PolicyConfig(**result)
   - On pydantic.ValidationError → raise PolicyLoadError with formatted validation errors
8. Return the PolicyConfig
```

**Pydantic error formatting:** Pydantic v2's `ValidationError` contains structured error info. Format it as:

```
Policy validation failed:
  - policies.0.check.op: Input should be 'equals', 'starts_with', ... (got 'regex')
  - policies.1.steps: Field required
```

Use `e.errors()` to iterate and format each error with its location path and message. This gives the developer field-level error reporting without writing custom validators for every field.

### `compile_regexes(config: PolicyConfig) -> CompiledPolicy`

```
1. Initialize regexes = {}
2. For each rule in config.policies:
   a. If rule.type == "param_rule" and rule.check.op == "matches":
      - key = f"{rule.name}:check.value"
      - Try re.compile(rule.check.value)
      - On re.error → raise PolicyLoadError(
          f"Rule '{rule.name}' (param_rule): invalid regex in check.value: {error}"
        )
      - regexes[key] = compiled_pattern
   b. If rule.type == "chain_rule":
      - For i, step in enumerate(rule.steps):
        - If step.output_matches is not None:
          - key = f"{rule.name}:steps.{i}.output_matches"
          - Try re.compile(step.output_matches)
          - On re.error → raise PolicyLoadError(...)
          - regexes[key] = compiled_pattern
        - If step.param_matches is not None:
          - For param_name, pattern in step.param_matches.items():
            - key = f"{rule.name}:steps.{i}.param_matches.{param_name}"
            - Try re.compile(pattern)
            - On re.error → raise PolicyLoadError(...)
            - regexes[key] = compiled_pattern
3. Return CompiledPolicy(config=config, regexes=regexes)
```

This is ~40 lines of code. Every regex is compiled exactly once at startup. The engine looks up compiled patterns by key at evaluation time.

### `load_and_compile(path: str | Path) -> CompiledPolicy`

Convenience function that chains the two:

```python
def load_and_compile(path: str | Path) -> CompiledPolicy:
    """Load a policy file and compile all regex patterns. Raises PolicyLoadError on any failure."""
    config = load_policy(path)
    return compile_regexes(config)
```

This is what the proxy calls at startup. One call, one result, one exception type.

---

## 6. Error Cases (from MVP Spec Section 5)

Every error case in the spec is covered:

| Error case (from spec) | How it's caught | Error message format |
|------------------------|-----------------|----------------------|
| Malformed YAML | `yaml.YAMLError` in `load_policy` step 4 | `"Failed to parse YAML: {yaml_error}"` (PyYAML includes line/col) |
| Unknown rule type | Pydantic discriminated union in step 7 | `"policies.N.type: Input should be 'tool_allow', 'tool_block', 'param_rule' or 'chain_rule'"` |
| Unknown detector name | Pydantic `DetectorsConfig` model in step 7 | `"detectors.{name}: Extra inputs are not permitted"` (requires `model_config = ConfigDict(extra="forbid")`) |
| Missing required field | Pydantic validation in step 7 | `"policies.N.tools: Field required"` |
| Regex compilation failure | `re.compile` in `compile_regexes` | `"Rule '{name}' ({type}): invalid regex in {field}: {re_error}"` |
| File not found | `Path.exists()` check in step 2 | `"Policy file not found: {path}"` |
| Empty file | `None` check in step 5 | `"Policy file is empty"` |

### Required model change: forbid extra fields on `DetectorsConfig`

The current `DetectorsConfig` in `models.py` does not reject unknown detector names. Add:

```python
class DetectorsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # ... existing fields ...
```

This ensures `detectors: { nosql_injection: true }` is rejected with a clear error. Without this, unknown detectors are silently ignored — a dangerous misconfiguration.

**Note:** This is the only change to `models.py` required by this issue. It's a one-line addition. If you'd prefer to keep `models.py` unchanged for this issue, the alternative is a manual check in `load_policy` that compares detector keys against the known set. The Pydantic approach is cleaner.

---

## 7. How This Integrates with the Engine (Issue #4 Preview)

The engine receives a `CompiledPolicy` and uses it as follows:

```python
def evaluate(tool_call: ToolCall, policy: CompiledPolicy, session: SessionStore) -> Decision:
    # Step 1: Detectors (uses policy.config.detectors to know which are enabled)
    # Step 2: tool_block rules (iterates policy.config.policies where type == "tool_block")
    # Step 3: tool_allow rules (iterates policy.config.policies where type == "tool_allow")
    # Step 4: param_rules (uses policy.regexes[f"{rule.name}:check.value"] for "matches" op)
    # Step 5: chain_rules (uses policy.regexes for output_matches and param_matches)
    # Step 6: default decision (policy.config.settings.default_decision)
```

The engine never calls `re.compile()`. It never touches YAML. It receives a fully validated, pre-compiled structure and evaluates it.

---

## 8. Test Plan

**File:** `tests/test_policy.py`

All tests are synchronous. Tests that need YAML files use `tmp_path` (pytest built-in fixture) to create temporary files. No subprocess, no I/O beyond temp file creation.

### Test 1: `test_load_minimal_policy`

**Setup:** Write a minimal valid YAML to temp file:
```yaml
version: "0.1"
```
**Assert:** `load_policy()` returns a `PolicyConfig` with `version == "0.1"`, default settings, default detectors, empty policies list.

### Test 2: `test_load_full_policy`

**Setup:** Write the golden path example policy (all 5 rules, all detectors enabled) to temp file.
**Assert:** `load_policy()` returns `PolicyConfig` with 5 rules. Assert first rule is `ToolAllowRule`, last rule is `ChainRule`. Assert `settings.default_decision == "allow"`.

### Test 3: `test_load_file_not_found`

**Call:** `load_policy("/nonexistent/path/agentgate.yaml")`
**Assert:** Raises `PolicyLoadError` with `"not found"` in the message.

### Test 4: `test_load_invalid_yaml`

**Setup:** Write `"policies: [{{invalid"` to temp file.
**Assert:** Raises `PolicyLoadError` with YAML parse error details.

### Test 5: `test_load_empty_file`

**Setup:** Write empty string to temp file.
**Assert:** Raises `PolicyLoadError` with `"empty"` in the message.

### Test 6: `test_load_unknown_rule_type`

**Setup:** Write policy with `type: "custom_rule"` in a policy entry.
**Assert:** Raises `PolicyLoadError`. Error message references the rule type.

### Test 7: `test_load_unknown_detector`

**Setup:** Write policy with `detectors: { nosql_injection: true }`.
**Assert:** Raises `PolicyLoadError`. Error message references the unknown detector.
**Requires:** `extra="forbid"` on `DetectorsConfig`.

### Test 8: `test_load_missing_required_field`

**Setup:** Write a `tool_allow` rule missing the `tools` field.
**Assert:** Raises `PolicyLoadError`. Error message includes `"tools"` and `"required"`.

### Test 9: `test_compile_regexes_valid`

**Setup:** Build a `PolicyConfig` programmatically with:
- A `param_rule` using `op: "matches"` and `value: ".*@mycompany\\.com$"`
- A `chain_rule` with `output_matches: "BEGIN.*PRIVATE KEY"` and `param_matches: {"to": "^(?!.*@mycompany\\.com$).*$"}`
**Assert:** `compile_regexes()` returns `CompiledPolicy` with 3 entries in `regexes` dict. Each key follows the `{name}:{path}` scheme. Each value is a `re.Pattern`. Verify one pattern matches an expected string.

### Test 10: `test_compile_regexes_invalid_pattern`

**Setup:** Build a `PolicyConfig` with a `param_rule` using `op: "matches"` and `value: "[invalid(regex"`.
**Assert:** Raises `PolicyLoadError` with the rule name and `"invalid regex"` in the message.

---

## 9. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | Valid YAML with all rule types loads into a correct `PolicyConfig` | Tests 1, 2 |
| AC-2 | File-level errors (not found, empty, malformed YAML) raise `PolicyLoadError` with actionable messages | Tests 3, 4, 5 |
| AC-3 | Schema-level errors (unknown rule type, unknown detector, missing fields) raise `PolicyLoadError` with field-level messages | Tests 6, 7, 8 |
| AC-4 | All regex patterns in `matches` ops and chain rules are pre-compiled into `CompiledPolicy.regexes` | Test 9 |
| AC-5 | Invalid regex patterns are caught at load time with rule name and pattern in the error message | Test 10 |

---

## 10. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Pydantic discriminated union error messages are cryptic | Medium | Low | Format `ValidationError.errors()` into human-readable lines. Test the actual error text in tests 6–8. |
| `extra="forbid"` on `DetectorsConfig` breaks existing tests | Low | Low | Only `test_models.py::TestPolicyConfig::test_minimal_config` constructs a `DetectorsConfig`. Check it doesn't pass unknown fields. |
| YAML anchors/aliases cause unexpected merges | Low | Low | `yaml.safe_load` handles these correctly. Not a real risk. |
| Large YAML files slow loading | Very Low | None | Policy files are <100 lines in practice. Not a concern. |
| Pydantic v2 `model_validate` vs `__init__` differences | Low | Low | Use `PolicyConfig(**data)` which Pydantic v2 handles correctly for dict input. Alternatively use `PolicyConfig.model_validate(data)` — either works. |

---

## 11. Design Constraints for Downstream Issues

1. **`CompiledPolicy` is the input to the engine.** Issue #4 receives `CompiledPolicy`, never raw YAML or uncompiled `PolicyConfig`. The engine trusts that all fields are valid and all regexes are compiled.

2. **Regex lookup key convention is `{rule_name}:{field_path}`.** The engine must use the same key scheme to look up patterns. This is the contract between loader and engine.

3. **`PolicyLoadError` is the only error type.** The proxy's startup code catches `PolicyLoadError`, prints the message, and exits with code 1. No other exception types escape from the policy module.

4. **`extra="forbid"` on `DetectorsConfig` is required.** Without it, typos in detector names are silently ignored — a security-relevant misconfiguration.

5. **Non-regex `param_rule` operators use literal comparison.** The engine does NOT look up compiled regexes for `equals`, `starts_with`, `ends_with`, `contains`, or `in` operators. Only `matches` goes through the regex map.

---

## 12. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/policy.py` | **Replace stub** | `PolicyLoadError`, `CompiledPolicy`, `load_policy()`, `compile_regexes()`, `load_and_compile()` |
| `src/agentgate/models.py` | **One-line change** | Add `model_config = ConfigDict(extra="forbid")` to `DetectorsConfig` |
| `tests/test_policy.py` | **Replace stub** | 10 unit tests |

No other files are touched.

---

## 13. Definition of Done

- [ ] `src/agentgate/policy.py` contains `PolicyLoadError`, `CompiledPolicy`, `load_policy()`, `compile_regexes()`, `load_and_compile()`
- [ ] `load_policy` parses YAML and validates against `PolicyConfig` with Pydantic
- [ ] All 7 error cases from MVP Spec Section 5 are handled with actionable error messages
- [ ] `compile_regexes` pre-compiles all regex patterns from `param_rule` (matches op) and `chain_rule` fields
- [ ] `CompiledPolicy.regexes` uses deterministic `{rule_name}:{field_path}` keys
- [ ] `DetectorsConfig` rejects unknown detector names via `extra="forbid"`
- [ ] `tests/test_policy.py` contains 10 tests, all passing
- [ ] No async code — pure synchronous functions only
- [ ] No dependency on `proxy.py` or `parser.py` — imports only `models.py`, `yaml`, `re`, `pathlib`
- [ ] All tests run in under 1 second (file I/O to tmp_path only)