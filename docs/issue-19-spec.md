# Issue #19 Spec: Write Evaluation Report

**Issue:** Write evaluation report (`docs/evaluation.md`)  
**Milestone:** PR3 — Evaluation + Demo  
**Depends on:** #16 (eval harness — implemented), #17 (25 scenarios — must be done first)  
**Blocked by:** Nothing downstream depends on #19 directly, but README update is part of scope.

---

## 1. What This Issue Delivers

A single file `docs/evaluation.md` that documents:

1. **Methodology** — how scenarios are structured, how grading works, what policy is used
2. **Results table** — BU, ASR, FPR, median latency overhead
3. **Per-scenario breakdown** — pass/fail per scenario with matched rule/detector
4. **Per-OWASP-ASI breakdown** — ASR by ASI category
5. **Analysis** — what works, what doesn't, known limitations, FP discussion
6. **Reproducibility** — exact command to reproduce results

Plus: a README update replacing the "Coming soon" placeholder in the Evaluation Results section with actual numbers.

---

## 2. Scope

### In scope

- `docs/evaluation.md` — complete evaluation methodology and results document
- README.md — replace "Coming soon" evaluation placeholder with final metrics table and link to full report
- Comparison table in README — update "Planned" entries to "✅" for chain detection and published eval metrics

### Out of scope

- Changing evaluation scenarios (that's #17)
- Changing the harness (that's #16)
- Implementing `agentgate eval` CLI (that's #20)
- `eval/report.py` programmatic generation (that's a convenience for #20; #19 is a hand-written document)
- Confidence intervals, statistical significance testing — not meaningful with 25 deterministic scenarios
- Comparison against other tools' benchmarks — no published numbers exist to compare against

---

## 3. Prerequisites — What Must Exist Before Writing

Before this issue can be executed, the following must be true:

1. **All 25 scenarios (#17) are implemented** and runnable via `run_all()` from `eval/harness.py`
2. **All 5 acceptance tests (#15) pass** — the report references AT-1 through AT-5 results
3. **The eval harness (#16) produces `EvalRun` results** with `ScenarioResult` objects containing `utility_pass`, `security_pass`, `step_results`, and `total_time_ms`
4. **The golden path demo policy** (`examples/policies/demo.yaml` or `agentgate.yaml.example`) is the default policy used for evaluation

If any scenario is flaky or fails unexpectedly, fix the scenario or detector before writing the report. The report must reflect passing results, not aspirational ones.

---

## 4. Document Structure — `docs/evaluation.md`

### 4.1 Header

```markdown
# AgentGate Evaluation Report

**Version:** 0.1.0  
**Date:** [date of generation]  
**Policy:** `agentgate.yaml.example` (golden path demo policy)  
**Scenarios:** 10 benign + 15 adversarial = 25 total  
**Engine version:** deterministic only (no ML, no probabilistic scoring)
```

### 4.2 Section: Methodology

Content to cover:

- **Scenario structure:** Each scenario is a sequence of `ScenarioStep` objects. Each step defines a tool call (tool name + arguments), an optional `simulated_response` (what the MCP server would return), and an `expect_decision` (allow or block).
- **Grading model:** Dual-metric, adapted from AgentDojo (NeurIPS 2024). Each scenario produces `utility_pass` (all expected-allow steps were allowed) and `security_pass` (all expected-block steps were blocked).
- **Session isolation:** Fresh `SessionStore` per scenario. No cross-scenario state leakage.
- **Policy used:** The golden path demo policy (`agentgate.yaml.example`) with all 5 detectors enabled, tool allowlist, param rules for path sandboxing and email restriction, and chain rule for exfiltration detection.
- **No LLM in the loop:** All scenarios are deterministic mock sequences. The harness drives `evaluate()` directly with hardcoded tool calls. This tests the policy engine, not LLM behavior. LLM-driven evaluation is a v1 goal.
- **Latency measurement:** `time.perf_counter()` around each `evaluate()` call. Median across all steps in all scenarios.

### 4.3 Section: Summary Results

A single table with the four target metrics:

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Benign Utility (BU) | ≥ 90% | X/10 (Y%) | ✅/❌ |
| Attack Success Rate (ASR) | ≤ 10% | X/15 (Y%) | ✅/❌ |
| False Positive Rate (FPR) | ≤ 10% | X/10 (Y%) | ✅/❌ |
| Median Latency Overhead | ≤ 15ms | Xms | ✅/❌ |

**Formulas** (restated for clarity):
- BU = (benign scenarios where all expected-allow steps were allowed) / (total benign scenarios)
- ASR = (adversarial scenarios where at least one expected-block step was allowed) / (total adversarial scenarios)
- FPR = (benign scenarios where at least one expected-allow step was blocked) / (total benign scenarios)
- Median latency = median of per-step `eval_time_ms` across all scenarios

### 4.4 Section: Per-Scenario Results

Two tables: benign and adversarial.

**Benign scenarios:**

| ID | Name | Steps | Utility Pass | Notes |
|----|------|-------|-------------|-------|
| B1 | Read file within allowed directory | 1 | ✅ | |
| B2 | List files in allowed directory | 1 | ✅ | |
| ... | ... | ... | ... | ... |

**Adversarial scenarios:**

| ID | Name | OWASP ASI | Steps | Security Pass | Blocking Layer | Notes |
|----|------|-----------|-------|--------------|----------------|-------|
| A1 | Path traversal /etc/passwd | ASI02 | 1 | ✅ | detector:path_traversal | |
| A2 | Relative path traversal | ASI02 | 1 | ✅ | detector:path_traversal | |
| ... | ... | ... | ... | ... | ... | ... |

The "Blocking Layer" column is critical — it shows whether the block came from a detector (step 1), tool_block (step 2), tool_allow (step 3), param_rule (step 4), or chain_rule (step 5). This demonstrates defense-in-depth.

### 4.5 Section: Results by OWASP ASI Category

| OWASP ASI | Category | Scenarios | ASR | Notes |
|-----------|----------|-----------|-----|-------|
| ASI01 | Goal Hijack / Indirect Injection | A11, A12, A15 | X% | Chain detection exercised |
| ASI02 | Tool Misuse | A1–A7, A13, A14 | X% | Detector coverage |
| ASI03 | Privilege / Data Abuse | A8, A9, A10 | X% | Secrets detector |

### 4.6 Section: Analysis

Cover these specific points:

1. **What works well:** Deterministic detectors achieve 100% detection on their respective pattern categories with zero flakiness. Chain detection correctly blocks multi-step exfiltration sequences.

2. **Known false positive risks:** Document any scenario where a benign call was blocked (if BU < 100%), with root cause. If BU = 100%, note the known accepted FP from `test_sql_injection.py` (`INSERT INTO` in English prose) and explain why it doesn't appear in the benign scenario set.

3. **Known limitations (be honest — this is a differentiator):**
   - Deterministic regex detectors can be evaded via encoding, Unicode normalization, or obfuscation (spec Section 11, Risk 2). This is explicitly out of scope for MVP.
   - Chain detection requires the sensitive data to appear in the tool response text. If the MCP server returns binary data or the response is not captured (parse failure), chain detection is bypassed.
   - No response scanning — tool outputs are not inspected for secrets or injection. Deferred to v1.
   - The `INSERT INTO` pattern has a known FP edge case in English prose. Accepted for MVP; narrowing to require SQL structural context (parenthesized column list) is a v1 refinement.
   - SQL injection detector does not flag `SELECT` statements — read-based SQL injection is not caught. This is a deliberate conservative scope decision to minimize FPR.

4. **Defense-in-depth observation:** Multiple blocking layers fire on the same attack. For example, AT-3 (chain exfiltration) is blocked by param_rule (external email) AND chain_rule (sensitive read → send). The report should note which layer fires first (param_rule, since it's step 4 vs chain_rule at step 5) and that both provide independent coverage.

### 4.7 Section: Reproducibility

```bash
# Install from source
git clone https://github.com/zihan001/agentgate.git
cd agentgate
pip install -e ".[dev]"

# Run all evaluation scenarios
python -c "
from eval.harness import run_all
from agentgate.policy import load_and_compile
from eval.scenarios import load_all_scenarios  # or however #17 exposes them

policy = load_and_compile('agentgate.yaml.example')
results = run_all(load_all_scenarios(), policy)
for r in results.results:
    status = '✅' if r.passed else '❌'
    print(f'{status} {r.scenario_id}: {r.scenario_name}')
"

# Or via CLI (if #20 is done)
agentgate eval --suite standard
```

**Note:** The exact reproduction command depends on how #17 exports scenarios and whether #20 is done. Provide both the Python API path (always works) and the CLI path (if available). Adjust when writing the actual document.

---

## 5. README Updates

### 5.1 Evaluation Results Section

Replace:

```markdown
## Evaluation Results

> Coming soon. Evaluation harness and published metrics are planned for v0.1.
```

With:

```markdown
## Evaluation Results

25 deterministic scenarios (10 benign + 15 adversarial) evaluated against the default policy with all detectors enabled:

| Metric | Target | Result |
|--------|--------|--------|
| Benign Utility (BU) | ≥ 90% | X% (Y/10) |
| Attack Success Rate (ASR) | ≤ 10% | X% (Y/15) |
| False Positive Rate (FPR) | ≤ 10% | X% (Y/10) |
| Median Latency | ≤ 15ms | Xms |

See [Evaluation Report](docs/evaluation.md) for full methodology, per-scenario results, and OWASP ASI category breakdown.
```

### 5.2 Comparison Table

Update the two "Planned" entries:

| Feature | AgentGate | ... |
|---------|-----------|-----|
| Chain detection | ~~Planned~~ → **✅** | ... |
| Published eval metrics | ~~Planned~~ → **✅** | ... |

### 5.3 Documentation Links

Add to the Documentation section:

```markdown
- [Evaluation Report](docs/evaluation.md)
```

---

## 6. Definition of Done

- [ ] `docs/evaluation.md` exists and contains all 7 sections from §4 above
- [ ] Summary results table shows actual numbers from running the 25 scenarios
- [ ] All four metrics meet MVP targets (BU ≥ 90%, ASR ≤ 10%, FPR ≤ 10%, latency ≤ 15ms)
- [ ] Per-scenario table lists all 25 scenarios with pass/fail status
- [ ] OWASP ASI breakdown table is populated
- [ ] Analysis section honestly documents at least 3 known limitations
- [ ] Reproducibility section provides a working command to regenerate results
- [ ] README evaluation placeholder replaced with actual metrics
- [ ] README comparison table updated (chain detection ✅, published eval metrics ✅)
- [ ] README documentation section links to `docs/evaluation.md`
- [ ] `ruff check docs/` passes (if any code blocks are included)
- [ ] All existing tests still pass (`uv run pytest`)

---

## 7. How to Execute This Issue

### Step 1: Run the scenarios and collect raw results

Write a short script (or use the Python REPL) to run all 25 scenarios via `run_all()` and dump the `EvalRun` object. Capture:
- Per-scenario: `scenario_id`, `passed`, `utility_pass`, `security_pass`, each step's `actual` decision and `matched_rule`/`matched_detector`
- Aggregate: count benign pass/fail, adversarial pass/fail, compute BU/ASR/FPR
- Latency: collect all `eval_time_ms` values, compute median

### Step 2: Verify targets are met

If any target is missed:
- **BU < 90%:** A benign scenario is being falsely blocked. Identify the scenario, check which detector or rule fires, and either fix the detector/rule or reclassify the scenario. Do NOT ship a report with failed targets unless there's a documented, defensible reason.
- **ASR > 10%:** An adversarial scenario is not being caught. This means a detector or rule is missing coverage. Fix the rule or add detector coverage.
- **FPR > 10%:** Same as BU < 90% (they're complementary).
- **Latency > 15ms:** Profile `evaluate()`. The regex compilation is done at policy load time, so per-call cost should be microseconds. If it's not, something is wrong.

### Step 3: Write the document

Fill in the template from §4 with actual numbers. The analysis section requires judgment — don't just dump numbers, explain what they mean and where the gaps are.

### Step 4: Update README

Make the three targeted edits from §5.

### Step 5: Run tests, commit

Ensure `uv run pytest` still passes. The evaluation report is a documentation artifact, not code, so no new tests are needed for this issue.

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Scenarios (#17) not done yet | High (it's the predecessor) | Blocks this entirely | Don't start #19 until #17 is merged and all 25 scenarios run cleanly |
| A target metric is not met | Medium | Forces detector/rule changes | Run scenarios early. Fix issues in #17 or detector code, not in the report |
| Report becomes too long | Low | Nobody reads it | Cap at ~300 lines of markdown. This is a technical artifact, not a thesis |
| Results change after report is written | Low | Stale numbers | Add a "generated on" date. Accept that the report is a snapshot, not a live dashboard |

---

## 9. What This Issue Is NOT

- **Not `eval/report.py`:** That module (#20 scope) is for programmatic metric computation and CLI output formatting. This issue produces a hand-written document with actual analysis and narrative. `report.py` can be used to generate the raw numbers, but the document itself is authored, not auto-generated.
- **Not a research paper:** No literature review, no related work section, no formal threat model (that's in the spec). Just: methodology, numbers, analysis, limitations.
- **Not a marketing page:** Honest about what doesn't work. The limitations section is as important as the results table. This is what distinguishes the project from competitors who claim effectiveness without evidence.