# Issue #20: Implement `agentgate eval` CLI Command

**Status:** Implementation-ready spec
**Depends on:** #16 (eval harness — ✅ done), #17 (25 scenarios — ✅ done)
**Blocked by:** Nothing — both dependencies are complete
**Estimated effort:** ~3 hours

---

## 1. What This Issue Delivers

A new `eval` subcommand on the `agentgate` CLI that:

1. Loads a policy file (default: `eval/policies/eval_reference.yaml`, overridable via `--policy`)
2. Runs all 25 scenarios (10 benign + 15 adversarial) through the evaluation harness
3. Computes four metrics: BU, ASR, FPR, median latency
4. Prints a formatted summary table to **stdout**
5. Optionally outputs full per-scenario JSON to stdout via `--json`

This also requires implementing `eval/report.py` (currently a stub) to compute and format metrics from `EvalRun` results.

---

## 2. Scope

### In Scope

- `agentgate eval` CLI command (Click subcommand added to `cli.py`)
- `eval/report.py` implementation: metric computation + plain-text table formatter + JSON formatter
- 7–10 tests covering CLI invocation, metric computation, output format, and edge cases

### Out of Scope

- OWASP ASI category breakdown in the table (stretch — noted in spec Section 12 but not required for MVP)
- CI/CD JSON export integration
- `--suite` flag (only one suite exists: `standard`)
- `--backend` flag (no LLM backend needed — scenarios are deterministic)
- CSV/HTML output formats
- Comparison to baseline (no-firewall) runs

---

## 3. Design Decisions

### 3.1 Output Goes to stdout, Diagnostics to stderr

Consistent with `agentgate logs` which outputs JSON Lines to stdout. The metrics table goes to stdout so it can be piped/captured. Progress messages (if any) go to stderr.

### 3.2 No `--backend` Flag

The MVP spec mentions `--backend openai:gpt-4o` in the aspirational CLI output (Spec Section D, Workflow 3), but all 25 scenarios are deterministic — they call `evaluate()` directly via the harness, not an LLM. A `--backend` flag is deferred. The command is simply `agentgate eval`.

### 3.3 Policy Resolution Order

1. `--policy <path>` if provided
2. Else: bundled `eval/policies/eval_reference.yaml` (shipped with the package)

The reference policy is the canonical evaluation policy. Users can override to test their own policies against the standard scenario suite.

### 3.4 `eval/report.py` Owns Metric Computation

The harness (`eval/harness.py`) returns raw `EvalRun` with per-scenario results. `eval/report.py` computes aggregate metrics from those results. This keeps the harness focused on execution and report on presentation — clean separation.

### 3.5 JSON Output Mode

`--json` outputs the full `EvalRun` plus computed metrics as a single JSON object to stdout. This is the machine-readable output for CI/CD integration. When `--json` is active, the human-readable table is suppressed.

---

## 4. CLI Interface

```
agentgate eval [--policy PATH] [--json] [--verbose]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--policy` | `click.Path()` | `eval/policies/eval_reference.yaml` (bundled) | Policy file to evaluate against |
| `--json` | `is_flag` | `False` | Output full results as JSON instead of summary table |
| `--verbose` / `-v` | `is_flag` | `False` | Enable debug logging to stderr |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All scenarios passed (every step matched expected decision) |
| 1 | One or more scenarios failed |
| 2 | Error loading policy or scenarios |

### Human-Readable Output (default)

```
AgentGate Evaluation Report
═══════════════════════════════════════════════════
Policy:     eval/policies/eval_reference.yaml
Scenarios:  25 (10 benign + 15 adversarial)

Results
───────────────────────────────────────────────────
Benign Utility (BU):      100.0%  (10/10)
Attack Success Rate (ASR):  0.0%  (0/15)
False Positive Rate (FPR):  0.0%  (0/10)
Median Latency:             0.06ms

Status: ✅ PASS — all scenarios matched expected decisions
───────────────────────────────────────────────────

Failures:
  (none)
```

If there are failures:

```
Status: ❌ FAIL — 2 scenario(s) with unexpected decisions

Failures:
  A11 step 1: expected block, got allow (Chain exfiltration — API key read then external send)
  B7 step 1: expected allow, got block (Read file then send email to internal address)
```

### JSON Output (`--json`)

```json
{
  "timestamp": "2026-03-16T...",
  "policy_source": "eval/policies/eval_reference.yaml",
  "scenario_count": 25,
  "metrics": {
    "benign_utility": 1.0,
    "benign_utility_fraction": "10/10",
    "attack_success_rate": 0.0,
    "attack_success_rate_fraction": "0/15",
    "false_positive_rate": 0.0,
    "false_positive_rate_fraction": "0/10",
    "median_latency_ms": 0.06,
    "all_passed": true
  },
  "results": [
    {
      "scenario_id": "B1",
      "scenario_name": "Read file within allowed directory",
      "category": "benign",
      "owasp_asi": null,
      "passed": true,
      "utility_pass": true,
      "security_pass": true,
      "total_time_ms": 0.04,
      "step_results": [...]
    }
  ]
}
```

---

## 5. Implementation Plan

### 5.1 `eval/report.py` — Metric Computation + Formatting

Replace the stub with:

```python
# eval/report.py

@dataclass(frozen=True)
class EvalMetrics:
    benign_total: int
    benign_utility_pass: int
    adversarial_total: int
    adversarial_security_pass: int
    # Derived
    benign_utility: float        # benign_utility_pass / benign_total
    attack_success_rate: float   # 1 - (adversarial_security_pass / adversarial_total)
    false_positive_rate: float   # 1 - (benign_utility_pass / benign_total)
    median_latency_ms: float
    all_passed: bool

def compute_metrics(eval_run: EvalRun) -> EvalMetrics:
    """Compute BU, ASR, FPR, median latency from an EvalRun."""

def format_table(eval_run: EvalRun, metrics: EvalMetrics, policy_source: str) -> str:
    """Render the human-readable summary table."""

def format_json(eval_run: EvalRun, metrics: EvalMetrics) -> str:
    """Render the full JSON output."""
```

**Metric definitions (from Spec Section 12):**

| Metric | Formula | Notes |
|--------|---------|-------|
| BU | `benign_utility_pass / benign_total` | `utility_pass` = all allow-expected steps were allowed |
| ASR | `1 - (adversarial_security_pass / adversarial_total)` | `security_pass` = all block-expected steps were blocked |
| FPR | `1 - (benign_utility_pass / benign_total)` | = `1 - BU` (equivalent for our scenario structure) |
| Median latency | `median(step.eval_time_ms for all steps)` | Across all steps in all scenarios |

**Edge case:** If `benign_total == 0` or `adversarial_total == 0`, report the missing metric as `N/A` (not division by zero). This shouldn't happen with the standard suite but protects against custom scenario sets.

### 5.2 `cli.py` — Add `eval` Subcommand

Add to the existing Click group in `cli.py`:

```python
@main.command(name="eval")
@click.option("--policy", default=None, type=click.Path(), help="...")
@click.option("--json", "json_output", is_flag=True, default=False, help="...")
@click.option("--verbose", "-v", is_flag=True, default=False, help="...")
def eval_cmd(policy, json_output, verbose):
    ...
```

**Implementation notes:**

- Import `eval.scenarios.ALL_SCENARIOS` and `eval.harness.run_all`
- Import `eval.report.compute_metrics`, `format_table`, `format_json`
- Load policy via `load_and_compile()` (same as `start` command)
- Default policy path: resolve relative to the package. Use `importlib.resources` or `Path(__file__)` traversal to find `eval/policies/eval_reference.yaml`. Since the eval directory is at repo root (not inside `src/agentgate/`), use `Path(__file__).parent.parent.parent / "eval" / "policies" / "eval_reference.yaml"` — but this breaks when installed via pip. **Decision:** For MVP (installed from source via `pip install -e .`), resolve relative to cwd or a known path. Accept that this won't work for a pip-installed package (PyPI publishing is deferred). Add a clear error message if the reference policy can't be found.
- Output table to stdout via `click.echo()`
- Set exit code based on `metrics.all_passed`

### 5.3 Scenario Discovery

Use the existing `eval.scenarios.ALL_SCENARIOS` list. No dynamic discovery, no plugin system.

---

## 6. File Changes

| File | Action | Description |
|------|--------|-------------|
| `eval/report.py` | **Replace stub** | `EvalMetrics` dataclass, `compute_metrics()`, `format_table()`, `format_json()` |
| `src/agentgate/cli.py` | **Add command** | `eval` subcommand with `--policy`, `--json`, `--verbose` |
| `tests/test_cli_eval.py` | **New file** | 7–10 tests for the eval CLI command |
| `tests/test_report.py` | **New file** | 8–10 tests for metric computation and formatting |
| `CLAUDE.md` | **Update** | Add `eval` command to CLI section, update `eval/report.py` status |

---

## 7. Test Plan

### `tests/test_report.py` — Metric Computation (8 tests)

| # | Test | Description |
|---|------|-------------|
| 1 | `test_compute_metrics_perfect_run` | All 25 pass → BU=1.0, ASR=0.0, FPR=0.0 |
| 2 | `test_compute_metrics_one_benign_failure` | 1 benign blocked → BU=0.9, FPR=0.1 |
| 3 | `test_compute_metrics_one_adversarial_failure` | 1 adversarial passes → ASR≈0.067 |
| 4 | `test_compute_metrics_all_fail` | Everything wrong → BU=0.0, ASR=1.0, FPR=1.0 |
| 5 | `test_compute_metrics_empty_benign` | 0 benign scenarios → benign metrics N/A, no crash |
| 6 | `test_compute_metrics_empty_adversarial` | 0 adversarial → adversarial metrics N/A, no crash |
| 7 | `test_compute_metrics_median_latency` | Verify median across all steps, not per-scenario |
| 8 | `test_format_table_contains_metrics` | Output string contains BU, ASR, FPR values |
| 9 | `test_format_json_valid` | Output is valid JSON, contains `metrics` and `results` keys |
| 10 | `test_format_json_metrics_match` | JSON metrics match compute_metrics output |

### `tests/test_cli_eval.py` — CLI Integration (7 tests)

| # | Test | Description |
|---|------|-------------|
| 1 | `test_eval_default_runs_and_passes` | `agentgate eval` with reference policy → exit 0, table in output |
| 2 | `test_eval_custom_policy` | `--policy` flag loads a different policy |
| 3 | `test_eval_json_output` | `--json` flag produces valid JSON on stdout |
| 4 | `test_eval_json_has_metrics` | JSON output contains `metrics.benign_utility` etc. |
| 5 | `test_eval_missing_policy_exits_2` | `--policy /nonexistent` → exit 2 |
| 6 | `test_eval_bad_policy_exits_2` | `--policy bad.yaml` → exit 2, error message |
| 7 | `test_eval_exit_1_on_failure` | Policy that causes failures → exit 1 |

**Test approach:** Use `CliRunner` (in-process, fast). For test 7, use a `default_decision: block` policy with all detectors off — this will block all benign scenarios, causing failures.

---

## 8. Default Policy Resolution — Detail

The reference policy lives at `eval/policies/eval_reference.yaml` (repo root, not inside `src/`). For MVP (source install only):

1. If `--policy` is provided, use it directly.
2. Else, try these in order:
   a. `./eval/policies/eval_reference.yaml` (cwd — works when running from repo root)
   b. `Path(__file__).resolve().parent.parent.parent / "eval" / "policies" / "eval_reference.yaml"` (relative to cli.py — works from any cwd during dev)
3. If neither exists, print error and exit 2.

This is pragmatic for MVP. When we move to PyPI (deferred), we'd bundle the policy as package data.

---

## 9. `format_table` Output Specification

The table renderer must produce exactly this structure (colors optional, controlled by tty detection):

```
AgentGate Evaluation Report
═══════════════════════════════════════════════════
Policy:     {policy_source}
Scenarios:  {total} ({benign_count} benign + {adversarial_count} adversarial)

Results
───────────────────────────────────────────────────
Benign Utility (BU):      {bu:.1%}  ({bu_num}/{bu_den})
Attack Success Rate (ASR): {asr:.1%}  ({asr_num}/{asr_den})
False Positive Rate (FPR): {fpr:.1%}  ({fpr_num}/{fpr_den})
Median Latency:            {latency:.2f}ms

Status: {✅ PASS | ❌ FAIL} — {summary_message}
───────────────────────────────────────────────────
```

If failures exist, append:

```
Failures:
  {scenario_id} step {step_index}: expected {expected}, got {actual} ({scenario_name})
```

**No ANSI color codes in the output string itself.** The CLI layer can wrap with color if `sys.stdout.isatty()`, but `format_table()` returns plain text.

---

## 10. Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| `eval/` not importable when installed via pip | Low (MVP is source-install only) | Clear error message. Fix when PyPI publishing is in scope. |
| Metric edge case: zero division | Low | Guard with `if total == 0` checks, report N/A |
| Output format bikeshedding | Low | Freeze the format in this spec. Iterate post-ship if needed. |

---

## 11. Definition of Done

- [ ] `eval/report.py` implements `EvalMetrics`, `compute_metrics()`, `format_table()`, `format_json()`
- [ ] `agentgate eval` CLI command runs all 25 scenarios and prints metrics table
- [ ] `--policy` flag overrides the default reference policy
- [ ] `--json` flag outputs machine-readable JSON
- [ ] Exit code 0 when all pass, 1 when failures, 2 on load errors
- [ ] `tests/test_report.py` — all metric computation tests pass
- [ ] `tests/test_cli_eval.py` — all CLI integration tests pass
- [ ] `ruff check` and `ruff format` clean
- [ ] `uv run pytest` — full suite green
- [ ] CLAUDE.md updated with eval command documentation