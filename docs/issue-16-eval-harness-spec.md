# Issue #16 — Evaluation Harness Spec

**Status:** Implementation-ready
**Depends on:** Engine (#4 ✅), Detectors (#21–#26 ✅), Session (#10 ✅), Chain (#11 ✅), param_rule (#8 ✅)
**Blocks:** #17 (scenarios), #19 (report), #20 (`agentgate eval` CLI)
**Estimated effort:** ~3 hours

---

## 1. What This Is

`eval/harness.py` — a standalone evaluation runner that loads scenario definitions, executes each one against the AgentGate engine (not the proxy — no subprocess, no I/O), grades utility and security outcomes, and returns structured results that `eval/report.py` (#19) can compute aggregate metrics from.

This is the **test infrastructure**, not the scenarios themselves (#17) or the CLI command (#20). It defines the scenario contract, the runner loop, and the result schema.

## 2. What This Is Not

- **Not a proxy integration test.** The harness drives `evaluate()` directly. Proxy-level acceptance tests already exist in `tests/test_acceptance.py`. The eval harness tests the policy engine's decision quality, not the transport layer.
- **Not an LLM-in-the-loop eval.** All scenarios are deterministic — hardcoded tool calls and simulated responses. No LLM API calls. LLM-dependent evaluation is a PR3 stretch goal if time allows; the harness should not block on it.
- **Not the report generator.** The harness returns structured `EvalResult` objects. Metric computation (BU, ASR, FPR) belongs in `eval/report.py` (#19).

## 3. Design Decisions

### 3.1 Engine-level, not proxy-level

**Decision:** Scenarios call `evaluate()` directly, managing `SessionStore` state in-process.

**Rationale:** Proxy-level evaluation adds subprocess overhead, LSP framing, and timing noise — none of which tests policy quality. The engine is where decisions happen. The proxy is already covered by integration tests. Keeping eval at the engine level means scenarios run in <1s total, are fully deterministic, and never flake.

### 3.2 Scenario as dataclass, not class hierarchy

**Decision:** Each scenario is a `Scenario` dataclass with a list of `ScenarioStep` dataclasses. No base class, no `utility() -> bool` / `security() -> bool` methods.

**Rationale:** The MVP spec (Section 12) mentions the AgentDojo pattern with `utility()` and `security()` methods. But our scenarios are deterministic tool-call sequences, not LLM-driven agent runs. A method-based interface adds abstraction without value — every scenario would implement the same pattern: "run these steps, check these assertions." A flat data structure is simpler, serializable (can be loaded from YAML later if needed), and easier to write 25 of.

### 3.3 Scenario definition format

```python
@dataclass(frozen=True)
class ScenarioStep:
    """One tool call in a scenario sequence."""
    tool_name: str
    arguments: dict[str, Any]
    simulated_response: str | None = None  # If set, recorded in session after allow
    expect_decision: Literal["allow", "block"] = "allow"
    description: str = ""  # Human-readable label for reporting

@dataclass(frozen=True)
class Scenario:
    """A complete evaluation scenario."""
    id: str                              # e.g. "B1", "A5"
    name: str                            # e.g. "Benign file read in sandbox"
    category: Literal["benign", "adversarial"]
    owasp_asi: str | None = None         # e.g. "ASI02", None for benign
    steps: list[ScenarioStep] = field(default_factory=list)
    policy_yaml: str | None = None       # Override policy; None = use default
    description: str = ""                # Detailed description for report
```

Multi-step scenarios (chain detection) are first-class: a scenario has N steps executed in order against a shared `SessionStore`. Each step declares its expected decision.

### 3.4 Result format

```python
@dataclass(frozen=True)
class StepResult:
    """Result of evaluating one step."""
    step_index: int
    tool_name: str
    expected: Literal["allow", "block"]
    actual: Literal["allow", "block"]
    passed: bool
    matched_rule: str | None
    matched_detector: str | None
    message: str | None
    eval_time_ms: float

@dataclass(frozen=True)
class ScenarioResult:
    """Result of running one scenario."""
    scenario_id: str
    scenario_name: str
    category: Literal["benign", "adversarial"]
    owasp_asi: str | None
    step_results: list[StepResult]
    passed: bool              # True iff ALL steps passed
    utility_pass: bool        # For benign: all allows were allowed
    security_pass: bool       # For adversarial: all blocks were blocked
    total_time_ms: float

@dataclass(frozen=True)
class EvalRun:
    """Complete evaluation run output."""
    timestamp: str            # ISO 8601
    policy_source: str        # Path or "inline"
    scenario_count: int
    results: list[ScenarioResult]
```

### 3.5 Default policy

The harness loads a default policy for all scenarios that don't override it. Default: `examples/policies/demo.yaml` — this is the golden-path policy exercising all 4 rule types and all 5 detectors. Scenarios can override with `policy_yaml` to test specific policy configurations (e.g., a chain-isolation policy that disables `secrets_in_params`).

### 3.6 Grading logic

A scenario **passes** if every step's actual decision matches its expected decision.

For metric computation downstream (#19):

- **Benign scenario:** `utility_pass = True` iff all steps with `expect_decision="allow"` got `actual="allow"`. A benign scenario with any false block → `utility_pass = False`.
- **Adversarial scenario:** `security_pass = True` iff all steps with `expect_decision="block"` got `actual="block"`. An adversarial scenario where the attack step was allowed → `security_pass = False`. Adversarial scenarios may include allowed preamble steps (e.g., a benign read before the exfil attempt); those allowed steps don't affect `security_pass`.

This grading is deterministic and needs no fuzzy matching.

## 4. Public API

```python
# eval/harness.py

def run_scenario(
    scenario: Scenario,
    default_policy: CompiledPolicy,
) -> ScenarioResult:
    """Run a single scenario against the engine. Returns structured result."""

def run_all(
    scenarios: list[Scenario],
    default_policy: CompiledPolicy,
) -> EvalRun:
    """Run all scenarios. Returns complete evaluation run."""
```

That's it. Two functions. `run_scenario` is the unit of work. `run_all` loops and assembles.

## 5. Implementation Plan

### 5.1 File: `eval/harness.py`

```
eval/
  harness.py      — Scenario, ScenarioStep, StepResult, ScenarioResult, EvalRun dataclasses
                    + run_scenario() + run_all()
```

All dataclasses and runner logic in one file. No separate models file — the eval module is self-contained and small.

### 5.2 `run_scenario()` logic

```
1. If scenario.policy_yaml is not None:
     Write to temp file, load_and_compile() → policy
   Else:
     Use default_policy
2. Create fresh SessionStore()
3. For each step in scenario.steps:
   a. Build ToolCall(tool_name=step.tool_name, arguments=step.arguments)
   b. time.perf_counter() start
   c. decision = evaluate(tool_call, policy, session)
   d. time.perf_counter() end → eval_time_ms
   e. If decision.action == "allow" and step.simulated_response is not None:
        entry = session.record_request(step.tool_name, step.arguments)
        session.record_response(entry, step.simulated_response)
      (This mirrors proxy behavior: only allowed calls get recorded in session)
   f. Build StepResult
4. Compute passed, utility_pass, security_pass from step results
5. Return ScenarioResult
```

Key detail: `simulated_response` is only recorded on allow. If a step is blocked, no session entry is created — matching the real proxy's behavior. This is critical for chain detection scenarios where step 1 must be allowed and its response recorded before step 2's chain rule can fire.

### 5.3 `run_all()` logic

```
1. timestamp = datetime.now(UTC).isoformat()
2. results = [run_scenario(s, default_policy) for s in scenarios]
3. Return EvalRun(timestamp, policy_source, len(scenarios), results)
```

Sequential. No parallelism needed — 25 scenarios with ~5 steps each at <1ms per eval = <1s total.

### 5.4 Temp file handling for policy overrides

Scenarios that set `policy_yaml` need a temp file for `load_and_compile()`. Use `tempfile.NamedTemporaryFile` with `delete=False`, load, then unlink. This keeps the harness self-contained without requiring callers to manage temp dirs.

Alternative considered: add a `compile_from_string()` function to `policy.py`. Rejected — `load_and_compile` is the only policy entry point and adding a string-based path changes the policy module's contract for one consumer. Temp file is simpler.

## 6. Test Plan

### File: `tests/test_eval_harness.py`

All tests are synchronous, no I/O except tmp_path for policy overrides. The harness is pure computation.

| # | Test | What it verifies |
|---|------|-----------------|
| 1 | `test_benign_scenario_all_allowed` | Single-step benign scenario → `passed=True`, `utility_pass=True`, `actual="allow"` |
| 2 | `test_adversarial_scenario_blocked` | Single-step adversarial with path traversal → `passed=True`, `security_pass=True`, `actual="block"` |
| 3 | `test_adversarial_false_negative` | Adversarial step that bypasses policy → `passed=False`, `security_pass=False` |
| 4 | `test_benign_false_positive` | Benign step blocked by overly aggressive policy → `passed=False`, `utility_pass=False` |
| 5 | `test_multi_step_chain_scenario` | Two-step chain: allow read (with simulated_response) → block send → correct grading |
| 6 | `test_simulated_response_only_on_allow` | Blocked step's simulated_response is NOT recorded in session |
| 7 | `test_policy_override_per_scenario` | Scenario with `policy_yaml` uses that policy, not default |
| 8 | `test_run_all_aggregates` | `run_all()` with 2 scenarios → `EvalRun` with correct count and both results |
| 9 | `test_eval_time_recorded` | `eval_time_ms > 0` for each step |
| 10 | `test_empty_scenario_list` | `run_all([])` → `EvalRun` with 0 results, no crash |

**10 tests total.** Focused on grading correctness and edge cases, not on re-testing the engine (that's already covered by 170+ existing tests).

## 7. Downstream Constraints

### For #17 (Scenarios)
- Import `Scenario`, `ScenarioStep` from `eval.harness`
- Each scenario file returns a `list[Scenario]`
- `simulated_response` is required on any allowed step whose output needs to be in session for subsequent chain detection steps
- `policy_yaml` override is available but should be used sparingly — most scenarios should work against the default demo policy

### For #19 (Report)
- Import `EvalRun`, `ScenarioResult` from `eval.harness`
- Metric formulas:
  - `BU = count(benign where utility_pass) / count(benign)`
  - `ASR = count(adversarial where NOT security_pass) / count(adversarial)`
  - `FPR = count(benign where NOT utility_pass) / count(benign)`
  - `median_latency = median(all step eval_time_ms)`
- Report should handle the edge case of 0 benign or 0 adversarial scenarios (division by zero)

### For #20 (`agentgate eval` CLI)
- CLI loads scenarios from #17, loads default policy, calls `run_all()`, passes `EvalRun` to report formatter from #19
- CLI should accept `--policy` to override the default policy path
- CLI should accept `--scenario` to run a single scenario by ID (filter before passing to `run_all`)

## 8. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Scenario format changes when writing #17 | Rework harness dataclasses | Keep dataclasses minimal — only fields needed for grading. No speculative fields. |
| Chain detection timing sensitivity | False results in chain scenarios | Session recording logic mirrors proxy exactly (record on allow only). Already validated in `test_chain_integration.py`. |
| Policy override temp file leaks | Disk clutter | Use try/finally with `os.unlink`. Not a real risk for 25 scenarios. |

## 9. Definition of Done

- [ ] `eval/harness.py` contains all dataclasses and both public functions
- [ ] 10 tests in `tests/test_eval_harness.py`, all passing
- [ ] `run_scenario` correctly handles: single-step, multi-step, chain detection, policy override
- [ ] Grading: `utility_pass` / `security_pass` / `passed` computed correctly for all scenario types
- [ ] `eval_time_ms` captured per step
- [ ] No new dependencies added (uses only existing agentgate modules + stdlib)
- [ ] `uv run pytest tests/test_eval_harness.py` passes clean
- [ ] `uv run ruff check eval/` passes clean

## 10. What Is Explicitly Out of Scope

- Scenario definitions (Issue #17)
- Metric computation and formatting (Issue #19)
- CLI command (Issue #20)
- LLM-in-the-loop evaluation
- Proxy-level evaluation
- JSON/YAML scenario serialization format (can be added later if scenarios grow)
- Parallel scenario execution
- Benchmark comparison (AgentGate vs no-firewall baseline — PR3 territory)