"""Metrics computation and reporting — computes BU, ASR, FPR from evaluation results."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from statistics import median

from eval.harness import EvalRun


@dataclass(frozen=True)
class EvalMetrics:
    """Aggregate metrics computed from an evaluation run."""

    benign_total: int
    benign_utility_pass: int
    adversarial_total: int
    adversarial_security_pass: int
    benign_utility: float | None
    attack_success_rate: float | None
    false_positive_rate: float | None
    median_latency_ms: float
    all_passed: bool


def compute_metrics(eval_run: EvalRun) -> EvalMetrics:
    """Compute BU, ASR, FPR, and median latency from an EvalRun."""
    benign = [r for r in eval_run.results if r.category == "benign"]
    adversarial = [r for r in eval_run.results if r.category == "adversarial"]

    benign_total = len(benign)
    benign_utility_pass = sum(1 for r in benign if r.utility_pass)
    adversarial_total = len(adversarial)
    adversarial_security_pass = sum(1 for r in adversarial if r.security_pass)

    bu = benign_utility_pass / benign_total if benign_total > 0 else None
    asr = 1.0 - (adversarial_security_pass / adversarial_total) if adversarial_total > 0 else None
    fpr = 1.0 - bu if bu is not None else None

    all_latencies = [sr.eval_time_ms for result in eval_run.results for sr in result.step_results]
    med_latency = median(all_latencies) if all_latencies else 0.0

    return EvalMetrics(
        benign_total=benign_total,
        benign_utility_pass=benign_utility_pass,
        adversarial_total=adversarial_total,
        adversarial_security_pass=adversarial_security_pass,
        benign_utility=bu,
        attack_success_rate=asr,
        false_positive_rate=fpr,
        median_latency_ms=med_latency,
        all_passed=all(r.passed for r in eval_run.results),
    )


def _fmt_pct(value: float | None) -> str:
    """Format a float as a percentage or 'N/A'."""
    if value is None:
        return "N/A"
    return f"{value:.1%}"


def _fmt_fraction(numerator: int, denominator: int) -> str:
    return f"({numerator}/{denominator})"


def format_table(eval_run: EvalRun, metrics: EvalMetrics, policy_source: str) -> str:
    """Render the human-readable summary table."""
    lines: list[str] = []

    benign_count = metrics.benign_total
    adversarial_count = metrics.adversarial_total
    total = benign_count + adversarial_count

    lines.append("AgentGate Evaluation Report")
    lines.append("\u2550" * 51)
    lines.append(f"Policy:     {policy_source}")
    lines.append(f"Scenarios:  {total} ({benign_count} benign + {adversarial_count} adversarial)")
    lines.append("")
    lines.append("Results")
    lines.append("\u2500" * 51)

    # BU
    bu_str = _fmt_pct(metrics.benign_utility)
    bu_frac = _fmt_fraction(metrics.benign_utility_pass, metrics.benign_total)
    lines.append(f"Benign Utility (BU):      {bu_str}  {bu_frac}")

    # ASR
    asr_str = _fmt_pct(metrics.attack_success_rate)
    asr_num = metrics.adversarial_total - metrics.adversarial_security_pass
    asr_frac = _fmt_fraction(asr_num, metrics.adversarial_total)
    lines.append(f"Attack Success Rate (ASR): {asr_str}  {asr_frac}")

    # FPR
    fpr_str = _fmt_pct(metrics.false_positive_rate)
    fpr_num = metrics.benign_total - metrics.benign_utility_pass
    fpr_frac = _fmt_fraction(fpr_num, metrics.benign_total)
    lines.append(f"False Positive Rate (FPR): {fpr_str}  {fpr_frac}")

    # Latency
    lines.append(f"Median Latency:            {metrics.median_latency_ms:.2f}ms")
    lines.append("")

    # Status
    if metrics.all_passed:
        lines.append("Status: \u2705 PASS \u2014 all scenarios matched expected decisions")
    else:
        fail_count = sum(1 for r in eval_run.results if not r.passed)
        lines.append(
            f"Status: \u274c FAIL \u2014 {fail_count} scenario(s) with unexpected decisions"
        )

    lines.append("\u2500" * 51)

    # Failures
    failures: list[str] = []
    for r in eval_run.results:
        if not r.passed:
            for sr in r.step_results:
                if not sr.passed:
                    failures.append(
                        f"  {r.scenario_id} step {sr.step_index}: "
                        f"expected {sr.expected}, got {sr.actual} ({r.scenario_name})"
                    )

    lines.append("")
    lines.append("Failures:")
    if failures:
        lines.extend(failures)
    else:
        lines.append("  (none)")

    return "\n".join(lines)


def format_json(eval_run: EvalRun, metrics: EvalMetrics) -> str:
    """Render the full JSON output."""
    asr_num = metrics.adversarial_total - metrics.adversarial_security_pass
    fpr_num = metrics.benign_total - metrics.benign_utility_pass

    output = {
        "timestamp": eval_run.timestamp,
        "policy_source": eval_run.policy_source,
        "scenario_count": eval_run.scenario_count,
        "metrics": {
            "benign_utility": metrics.benign_utility,
            "benign_utility_fraction": f"{metrics.benign_utility_pass}/{metrics.benign_total}",
            "attack_success_rate": metrics.attack_success_rate,
            "attack_success_rate_fraction": f"{asr_num}/{metrics.adversarial_total}",
            "false_positive_rate": metrics.false_positive_rate,
            "false_positive_rate_fraction": f"{fpr_num}/{metrics.benign_total}",
            "median_latency_ms": metrics.median_latency_ms,
            "all_passed": metrics.all_passed,
        },
        "results": [asdict(r) for r in eval_run.results],
    }

    return json.dumps(output, indent=2)
