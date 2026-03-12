# Issue #4: Implement Rule Engine (tool_allow + tool_block)

**Status:** Implementation-ready  
**Milestone:** PR1 — First End-to-End Interception  
**Depends on:** #3 (YAML policy loader — COMPLETE)  
**Blocks:** #5 (end-to-end wiring), #8 (param_rule evaluation)  
**Target file:** `src/agentgate/engine.py`  
**Test file:** `tests/test_engine.py`  
**Estimated effort:** 1.5–2 hours  
**Ref:** MVP Spec Section 5 (Precedence / Decision Model, steps 2–3, 6)

---

## 1. Objective

Evaluate a `ToolCall` against a `CompiledPolicy` and return a `Decision`. For this issue, implement only three layers of the decision stack: `tool_block` (step 2), `tool_allow` (step 3), and default decision (step 6). Detectors (step 1), `param_rule` (step 4), and `chain_rule` (step 5) are deferred — the engine must be structured so they slot in cleanly later without changing the function signature.

This is the core decision function. Everything downstream depends on its interface being correct. The function is pure, synchronous, and fast (<1ms).

---

## 2. Scope

### In scope

- `evaluate(tool_call: ToolCall, policy: CompiledPolicy) -> Decision` function in `src/agentgate/engine.py`
- `tool_block` evaluation: if tool is on any blocklist, block
- `tool_allow` evaluation: if any allowlist exists and tool is not on any allowlist, block
- Default decision fallthrough from `policy.config.settings.default_decision`
- Blocklist-beats-allowlist precedence
- Multiple `tool_allow` rules merge their tool sets
- Multiple `tool_block` rules merge their tool sets
- 10 unit tests

### Out of scope

- Detector pipeline (step 1 — Issue #26, wired in PR2)
- `param_rule` evaluation (step 4 — Issue #8)
- `chain_rule` evaluation (step 5 — Issue #11)
- Session store integration
- Audit logging
- Any async code

---

## 3. Technical Decisions

### Decision 1: Synchronous pure function

**Choice:** `evaluate()` is sync, stateless, no side effects.

**Rationale:** Policy evaluation is CPU-bound and fast. The proxy calls it via `await asyncio.to_thread(engine.evaluate, ...)` or just calls it directly since it's <1ms. No reason to make it async. Keeping it sync means trivial testing, no concurrency bugs, no event loop dependency.

### Decision 2: Function signature designed for expansion

**Choice:** `evaluate(tool_call: ToolCall, policy: CompiledPolicy) -> Decision`

**Rationale:** When detectors and param/chain rules are added later, the signature expands to `evaluate(tool_call: ToolCall, policy: CompiledPolicy, session: SessionStore | None = None, detector_results: list[DetectorResult] | None = None) -> Decision`. The `session` and `detector_results` params are optional with `None` defaults, so existing call sites don't break. For this issue, only `tool_call` and `policy` are used.

Note: an alternative is passing `detector_results` in now and accepting an empty list. Either works. The key constraint is: the function signature must not change in a breaking way when PR2 adds detectors/param_rules/chain_rules.

### Decision 3: Collect all blocklist/allowlist tools once, not per-rule

**Choice:** Pre-collect the union of all `tool_block` tools and all `tool_allow` tools at the start of `evaluate()`, then check membership.

**Rationale:** Iterating rules to check each individually is O(rules × call) instead of O(rules + call). More importantly, it matches the spec semantics: "Multiple `tool_allow` rules merge their tool lists" and "Blocklist takes precedence over allowlist." Building merged sets makes this precedence trivially correct.

### Decision 4: `matched_rule` reports the first matching rule name

**Choice:** When a tool is blocked by a blocklist, `Decision.matched_rule` is the `name` of the first `tool_block` rule that contains that tool. When blocked by allowlist absence, it's the name of the first `tool_allow` rule (convention: "not on allowlist").

**Rationale:** Audit logs and error messages need a human-readable rule reference. The "first matching" convention is simple and deterministic. For merged sets, reporting the first rule that contributed the match is sufficient.

### Decision 5: No dependency on `proxy.py` or `parser.py`

**Choice:** `engine.py` imports only from `models.py` and `policy.py` (`CompiledPolicy`).

**Rationale:** Leaf module in the import chain. Proxy depends on engine, never the reverse.

---

## 4. Implementation

### `evaluate(tool_call: ToolCall, policy: CompiledPolicy) -> Decision`

```
1. Collect blocked_tools: set[str] from all ToolBlockRule.tools in policy.config.policies
2. Collect allow_rules: list[ToolAllowRule] from policy.config.policies
3. Compute allowed_tools: set[str] = union of all ToolAllowRule.tools (empty if no allow rules)
4. has_allowlist = len(allow_rules) > 0

5. STEP 2 — tool_block:
   If tool_call.tool_name in blocked_tools:
     Find the first ToolBlockRule whose .tools contains tool_call.tool_name
     Return Decision(
       action="block",
       matched_rule=rule.name,
       message=f"Tool '{tool_call.tool_name}' is blocked by policy"
     )

6. STEP 3 — tool_allow:
   If has_allowlist and tool_call.tool_name not in allowed_tools:
     Find the first ToolAllowRule (for rule name reference)
     Return Decision(
       action="block",
       matched_rule=rule.name,
       message=f"Tool '{tool_call.tool_name}' is not on the allowlist"
     )

7. STEP 6 — default:
   Return Decision(
     action=policy.config.settings.default_decision,
     message=None
   )
```

This is ~30 lines of code. The function will grow when param_rule and chain_rule are added (Issue #8, #11), but the structure — early-return on block, fallthrough to default — stays the same.

### Placeholder comments for future steps

Include clearly marked sections where detectors, param_rules, and chain_rules will be inserted:

```python
def evaluate(tool_call: ToolCall, policy: CompiledPolicy) -> Decision:
    # --- Step 1: Detectors (Issue #26) ---
    # Will short-circuit here if any detector fires

    # --- Step 2: tool_block ---
    ...

    # --- Step 3: tool_allow ---
    ...

    # --- Step 4: param_rule (Issue #8) ---
    # Will iterate param_rules top-to-bottom here

    # --- Step 5: chain_rule (Issue #11) ---
    # Will check session history here

    # --- Step 6: default decision ---
    ...
```

This makes it obvious to the next issue (or future you) exactly where to insert code.

---

## 5. Edge Cases

| Case | Behavior | Rationale |
|------|----------|-----------|
| No `tool_block` rules in policy | Skip step 2 entirely | No blocklist = nothing to block |
| No `tool_allow` rules in policy | Skip step 3 entirely | No allowlist = all tools implicitly allowed (modulo other rules) |
| Tool on BOTH blocklist and allowlist | Blocked | Spec: "Blocklist takes precedence over allowlist" |
| Multiple `tool_allow` rules | Merge tool sets (union) | Spec: "Multiple `tool_allow` rules merge their tool lists" |
| Multiple `tool_block` rules | Merge tool sets (union) | Same logic as allowlist merging |
| `default_decision: block` with no rules | Every tool call blocked | Correct — restrictive default with no explicit allows means deny-all |
| `default_decision: allow` with no rules | Every tool call allowed | Correct — permissive default, useful with detectors-only policy |
| Empty `tools` list on a `tool_allow` rule | Acts as deny-all for tools | If allowlist exists but is empty, nothing is allowed. This is a valid (if unusual) config. |

---

## 6. Test Plan

**File:** `tests/test_engine.py`

All tests are synchronous. No fixtures, no subprocess, no I/O. Tests construct `CompiledPolicy` objects programmatically (using `compile_regexes` from `policy.py` or building directly since these tests have no regexes).

### Helper

```python
def _make_policy(**kwargs) -> CompiledPolicy:
    """Build a CompiledPolicy from keyword args. Shortcut for tests."""
    config = PolicyConfig(version="0.1", **kwargs)
    return CompiledPolicy(config=config, regexes={})
```

### Test 1: `test_allow_by_default`

**Setup:** Policy with no rules, `default_decision: allow`.  
**Input:** `ToolCall(tool_name="read_file", arguments={})`  
**Assert:** `decision.action == "allow"`, `matched_rule is None`

### Test 2: `test_block_by_default`

**Setup:** Policy with no rules, `default_decision: block`.  
**Input:** `ToolCall(tool_name="read_file", arguments={})`  
**Assert:** `decision.action == "block"`, `matched_rule is None`

### Test 3: `test_tool_on_allowlist_allowed`

**Setup:** Policy with one `tool_allow` rule listing `["read_file", "write_file"]`.  
**Input:** `ToolCall(tool_name="read_file", arguments={})`  
**Assert:** `decision.action == "allow"`

### Test 4: `test_tool_not_on_allowlist_blocked`

**Setup:** Same policy as Test 3.  
**Input:** `ToolCall(tool_name="delete_file", arguments={})`  
**Assert:** `decision.action == "block"`, `matched_rule` is the allowlist rule name, `message` contains "not on the allowlist"

### Test 5: `test_tool_on_blocklist_blocked`

**Setup:** Policy with one `tool_block` rule listing `["delete_file", "execute_shell"]`.  
**Input:** `ToolCall(tool_name="delete_file", arguments={})`  
**Assert:** `decision.action == "block"`, `matched_rule` is the blocklist rule name, `message` contains "blocked"

### Test 6: `test_tool_not_on_blocklist_allowed`

**Setup:** Same policy as Test 5, `default_decision: allow`.  
**Input:** `ToolCall(tool_name="read_file", arguments={})`  
**Assert:** `decision.action == "allow"`

### Test 7: `test_blocklist_beats_allowlist`

**Setup:** Policy with a `tool_allow` rule listing `["read_file", "delete_file"]` and a `tool_block` rule listing `["delete_file"]`.  
**Input:** `ToolCall(tool_name="delete_file", arguments={})`  
**Assert:** `decision.action == "block"`, `matched_rule` is the blocklist rule name (not the allowlist)

### Test 8: `test_multiple_allowlist_rules_merge`

**Setup:** Two `tool_allow` rules: one with `["read_file"]`, another with `["write_file"]`.  
**Input:** `ToolCall(tool_name="write_file", arguments={})`  
**Assert:** `decision.action == "allow"` (tool is in the merged allowlist)

### Test 9: `test_multiple_blocklist_rules_merge`

**Setup:** Two `tool_block` rules: one with `["delete_file"]`, another with `["execute_shell"]`.  
**Input:** `ToolCall(tool_name="execute_shell", arguments={})`  
**Assert:** `decision.action == "block"`

### Test 10: `test_no_allowlist_means_all_tools_pass_to_default`

**Setup:** Policy with only a `tool_block` rule listing `["delete_file"]`, `default_decision: allow`.  
**Input:** `ToolCall(tool_name="anything_else", arguments={})`  
**Assert:** `decision.action == "allow"` (no allowlist means no allowlist filtering, and tool isn't blocked, so default applies)

---

## 7. Acceptance Criteria

| # | Criterion | Verification |
|---|-----------|-------------|
| AC-1 | Tool on blocklist is blocked with correct `matched_rule` and message | Tests 5, 7, 9 |
| AC-2 | Tool not on allowlist is blocked when any allowlist exists | Tests 4, 7 |
| AC-3 | Blocklist takes precedence over allowlist | Test 7 |
| AC-4 | Multiple rules of same type merge their tool sets | Tests 8, 9 |
| AC-5 | Default decision applies when no rule matches | Tests 1, 2, 6, 10 |

---

## 8. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Function signature needs breaking change for PR2 | Low | Medium | Designed with optional params from the start. `session` and `detector_results` default to `None`. |
| `ParamRule` and `ChainRule` in `policy.config.policies` cause confusion when iterating | Low | Low | Use `isinstance` checks. Only process `ToolBlockRule` and `ToolAllowRule` in this issue. Others are skipped. |
| Performance concern with set construction on every call | Very Low | None | Set construction from <10 rules is nanoseconds. Not a real concern. Could be cached on `CompiledPolicy` later if profiling shows need (it won't). |

---

## 9. Design Constraints for Downstream Issues

1. **The `evaluate` signature is the contract.** Issue #5 calls `evaluate(tool_call, policy)`. When PR2 adds detectors, the call becomes `evaluate(tool_call, policy, session=session, detector_results=results)`. The function handles `None` defaults gracefully.

2. **Evaluation order is fixed.** Steps 1→2→3→4→5→6. Each step either returns a `Decision` (short-circuit) or falls through. Issue #8 adds step 4 code between step 3 and step 6. Issue #11 adds step 5. Issue #26 adds step 1. None of these restructure the function — they insert blocks at marked locations.

3. **`Decision.matched_rule` is always a rule name string or `None`.** The proxy uses this for error messages and audit logging. Downstream issues must populate it consistently.

4. **The engine never mutates the `CompiledPolicy` or `ToolCall`.** Pure read-only evaluation.

---

## 10. File Inventory

| File | Status | Contents |
|------|--------|----------|
| `src/agentgate/engine.py` | **Replace stub** | `evaluate()` function with steps 2, 3, 6 and placeholder comments for 1, 4, 5 |
| `tests/test_engine.py` | **Replace stub** | 10 unit tests |

No other files are touched.

---

## 11. Definition of Done

- [ ] `src/agentgate/engine.py` contains `evaluate(tool_call, policy) -> Decision`
- [ ] `tool_block` rules block matching tools with correct `matched_rule` and `message`
- [ ] `tool_allow` rules block non-listed tools when any allowlist exists
- [ ] Blocklist takes precedence over allowlist
- [ ] Multiple rules of the same type merge their tool sets
- [ ] Default decision applies when no rule matches
- [ ] Placeholder comments mark where steps 1, 4, 5 will be inserted
- [ ] `tests/test_engine.py` contains 10 tests, all passing
- [ ] No async code — pure synchronous function
- [ ] No dependency on `proxy.py` or `parser.py` — imports only `models.py` and `policy.py`
- [ ] All tests run in under 1 second