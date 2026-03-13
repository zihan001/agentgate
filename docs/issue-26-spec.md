# Issue #26 — Wire Detectors into Registry + Engine Pipeline

**Status:** Implementation-ready  
**Depends on:** #21 ✅, #22 ✅, #23 ✅, #24 ✅, #25 ✅  
**Blocks:** #15 (acceptance tests)  
**Estimated effort:** ~2 hours  

---

## 1. What This Issue Does

Connects the 5 implemented detectors (`sql_injection`, `path_traversal`, `command_injection`, `ssrf`, `secrets`) into a working pipeline, and wires that pipeline into the engine's decision stack as Step 1 (highest precedence, not overridable by policy rules).

After this issue, a tool call containing a path traversal payload will be blocked by the engine *before* any policy rules are evaluated — even if no policy file is loaded.

---

## 2. Scope

### In scope

- Implement `run_all()` in `detectors/__init__.py`
- Add Step 1 (detector invocation) to `engine.evaluate()`
- Integration tests proving the full pipeline works end-to-end

### Out of scope

- Chain detection (Issue #11 — separate detector, separate wiring path through session store)
- Detector configuration beyond boolean enable/disable (no per-detector thresholds, no custom patterns)
- Any changes to detector logic itself (those are locked in #21–#25)
- Audit logging of detector matches (Issue #12)

---

## 3. Changes Required

### 3.1 `src/agentgate/detectors/__init__.py` — Implement `run_all()`

**Current state:** `REGISTRY` dict maps 5 detector names to module paths. `run_all()` raises `NotImplementedError`.

**Target state:** `run_all()` imports each enabled detector module, calls `detect(tool_call)`, collects results.

**Design decisions:**

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Import strategy | Eager imports at module level, not lazy `importlib` | All 5 detectors are always available. Lazy import adds complexity for zero benefit — there's no plugin system in MVP. The `REGISTRY` dict with module path strings was scaffolding; replace with direct imports. |
| Return value | List of `DetectorResult` where `matched=True` only | Caller (engine) needs to know *which* detectors fired and *why*. Returning only matched results keeps the list short and avoids the engine filtering. |
| Short-circuit? | No — run all enabled detectors, return all matches | The engine will block on the *first* match regardless, but returning all matches is valuable for audit logging (#12) and for the user to see the full picture. Cost is negligible (5 regex scans over the same params). |
| Error handling | If a detector raises, log warning and skip it — don't crash the proxy | A regex bug in one detector shouldn't take down the entire pipeline. Log the exception, continue to next detector. |

**Implementation sketch:**

```python
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentgate.models import DetectorResult, ToolCall

from agentgate.detectors import (
    command_injection,
    path_traversal,
    secrets,
    sql_injection,
    ssrf,
)

log = logging.getLogger("agentgate.detectors")

# Maps config field name -> detector module
_DETECTORS: dict[str, object] = {
    "sql_injection": sql_injection,
    "path_traversal": path_traversal,
    "command_injection": command_injection,
    "ssrf_private_ip": ssrf,
    "secrets_in_params": secrets,
}


def run_all(tool_call: ToolCall, enabled: dict[str, bool]) -> list[DetectorResult]:
    results: list[DetectorResult] = []
    for name, module in _DETECTORS.items():
        if not enabled.get(name, False):
            continue
        try:
            result = module.detect(tool_call)
            if result.matched:
                results.append(result)
        except Exception:
            log.warning("Detector '%s' raised an exception, skipping", name, exc_info=True)
    return results
```

**Key detail:** The `enabled` dict comes from `DetectorsConfig.model_dump()` — its keys are `sql_injection`, `path_traversal`, `command_injection`, `ssrf_private_ip`, `secrets_in_params`. The `_DETECTORS` dict must use the same keys. This is already true in the current `REGISTRY`.

**What to remove:** Delete the `REGISTRY` dict (replaced by `_DETECTORS`). Delete the `NotImplementedError` stub.

---

### 3.2 `src/agentgate/engine.py` — Add Step 1 (Detectors)

**Current state:** `evaluate()` has a comment placeholder `# --- Step 1: Detectors (Issue #26) ---`. Steps 2–3 (tool_block, tool_allow) and Step 6 (default) are implemented.

**Target state:** Step 1 calls `detectors.run_all()`, and if any detector matched, returns a `block` Decision immediately (short-circuit).

**Design decisions:**

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Signature change? | No — `evaluate(tool_call, policy)` stays the same | The `policy.config.detectors` field provides the enabled map. No new args needed. |
| Which detector name goes in `matched_detector`? | First matched detector's name | Multiple detectors may fire. The Decision model has a single `matched_detector` string field. Use the first one — it's sufficient for the block message. All matches will be available in the audit log (Issue #12). |
| Message format | `"Blocked by detector: {detector_name}: {detail}"` | Clear, actionable, includes the specific finding. |
| What if policy is passthrough (no detectors config)? | Detectors still use defaults (all enabled) | `DetectorsConfig()` defaults all 5 to `True`. So even a minimal/empty policy runs all detectors. This is the correct security posture — detectors are the safety net. |

**Implementation sketch:**

```python
from agentgate.detectors import run_all as run_detectors

def evaluate(tool_call: ToolCall, policy: CompiledPolicy) -> Decision:
    # --- Step 1: Detectors ---
    detector_results = run_detectors(
        tool_call, policy.config.detectors.model_dump()
    )
    if detector_results:
        first = detector_results[0]
        return Decision(
            action="block",
            matched_detector=first.detector_name,
            message=first.detail,
        )

    # --- Step 2: tool_block --- (existing code, unchanged)
    ...
```

**What changes:** ~8 lines added at the top of `evaluate()`. No other changes to engine.py.

---

### 3.3 `src/agentgate/proxy.py` — No changes required

The proxy already calls `evaluate(parsed.tool_call, policy)` and checks `decision.action == "block"`. The `error_data` dict already includes `matched_detector`. No proxy changes needed.

**However**, there is one gap: when the proxy runs in **passthrough mode** (`self.policy is None`), it skips `evaluate()` entirely and uses the plain `_relay` function. This means **detectors don't run in passthrough mode**. This is correct for MVP — passthrough means "no policy loaded, no enforcement." If you want detectors-always-on even without a policy file, that's a separate design decision for later. Document this as a known behavior, not a bug.

---

## 4. Test Plan

### 4.1 Unit tests for `run_all()` — `tests/test_detectors/test_registry.py`

| # | Test | What it proves |
|---|------|----------------|
| 1 | `run_all` with all detectors enabled, clean tool call → empty list | No false positives from the pipeline itself |
| 2 | `run_all` with all enabled, tool call with `../../etc/passwd` in path param → list contains path_traversal result | Single detector fires correctly |
| 3 | `run_all` with all enabled, tool call with `../../etc/passwd` AND `AKIA1234567890ABCDEF` → list contains both path_traversal and secrets results | Multiple detectors fire, both returned |
| 4 | `run_all` with `path_traversal: false`, tool call with `../../etc/passwd` → empty list | Disabled detector is skipped |
| 5 | `run_all` with all enabled, SQL injection payload → list contains sql_injection result | Wiring to sql_injection module works |
| 6 | `run_all` with all enabled, SSRF payload (`http://169.254.169.254/`) → list contains ssrf result | Wiring to ssrf module works |
| 7 | `run_all` with all enabled, command injection payload (``; rm -rf /``) → list contains command_injection result | Wiring to command_injection module works |
| 8 | `run_all` with empty `enabled` dict → empty list | All detectors skipped when none enabled |

All tests are sync, no I/O. Use `ToolCall(tool_name="test_tool", arguments={...})` directly.

### 4.2 Engine integration tests — `tests/test_engine.py` (extend existing)

| # | Test | What it proves |
|---|------|----------------|
| 9 | Engine blocks on path traversal even when tool is on allowlist | Detectors take precedence over tool_allow (Spec Section 5 precedence) |
| 10 | Engine blocks on secrets even when no policy rules defined (default allow) | Detectors fire before default decision |
| 11 | Engine returns `matched_detector` field (not `matched_rule`) for detector blocks | Decision metadata is correct |
| 12 | Engine allows clean tool call that passes detectors and is on allowlist | Detectors don't interfere with normal flow |

### 4.3 Proxy integration test — `tests/test_proxy_policy.py` (extend existing)

| # | Test | What it proves |
|---|------|----------------|
| 13 | Proxy with policy, tool call with path traversal → JSON-RPC error returned to agent with detector info in `data` | Full end-to-end: proxy → parser → detectors → engine → error response |

This test uses the existing `proxy_with_policy` fixture. Policy: default allow, all detectors enabled, tool on allowlist. Tool call: `read_file(path="/etc/passwd")`. Expected: JSON-RPC error with `matched_detector: "path_traversal"` in the error data.

---

## 5. Acceptance Criteria

- [ ] `run_all()` in `detectors/__init__.py` is implemented (no more `NotImplementedError`)
- [ ] `engine.evaluate()` calls detectors as Step 1 and short-circuits on match
- [ ] A tool call with a path traversal payload is blocked by the engine even if the tool is on the allowlist
- [ ] A tool call with both a path traversal and a secret returns a block decision with the first detector's name
- [ ] Disabled detectors are not invoked
- [ ] All existing tests (88 total across PR1) continue to pass — no regressions
- [ ] All 13 new tests pass
- [ ] `ruff check` and `ruff format` clean

---

## 6. Files Changed

| File | Change type | Lines (est.) |
|------|-------------|-------------|
| `src/agentgate/detectors/__init__.py` | Rewrite | ~35 |
| `src/agentgate/engine.py` | Add ~8 lines | ~8 |
| `tests/test_detectors/test_registry.py` | New file | ~120 |
| `tests/test_engine.py` | Add 4 tests | ~50 |
| `tests/test_proxy_policy.py` | Add 1 test | ~25 |

**Total:** ~240 lines of new/changed code.

---

## 7. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Import cycle between `detectors/__init__` and detector modules | Low | Blocks startup | Detector modules don't import from `__init__`. One-way dependency. Verified by existing detector tests. |
| `DetectorsConfig.model_dump()` key mismatch with `_DETECTORS` keys | Medium | Silent detector skip | Test #4 explicitly verifies disabled behavior, and tests #2–#7 verify each detector fires. Any key mismatch → test failure. |
| Existing proxy integration tests break because detectors now fire on payloads that were previously allowed | Medium | CI red | Review existing test fixtures. The echo MCP server tests use tool names like `echo` with simple string args — unlikely to trigger detectors. If any do, update the test payloads to be detector-clean. |

The third risk is the most likely to bite. **Before writing any code, grep existing test fixtures for strings that might match detector patterns** (e.g., any test that passes a path like `/etc/` or a string containing `DROP`).

---

## 8. Implementation Order

1. **Grep existing tests** for detector-triggering payloads. Fix any that would break.
2. **Implement `run_all()`** in `detectors/__init__.py`. Run the 8 new unit tests.
3. **Wire Step 1 into `engine.evaluate()`**. Run the 4 new engine tests + all existing engine tests.
4. **Add proxy integration test**. Run full test suite.
5. **`ruff check && ruff format`**. Commit.

Estimated wall time: 1.5–2 hours.