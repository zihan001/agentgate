"""YAML policy loader — parses agentgate.yaml, validates schema, compiles regex patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import ValidationError

from agentgate.models import ChainRule, ParamRule, PolicyConfig


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be loaded, parsed, or validated."""

    pass


@dataclass(frozen=True)
class CompiledPolicy:
    """A fully validated and compiled policy, ready for the rule engine."""

    config: PolicyConfig
    regexes: dict[str, re.Pattern]


def load_policy(path: str | Path) -> PolicyConfig:
    """Load a YAML policy file and validate it against the PolicyConfig schema.

    Raises PolicyLoadError on any file, parse, or validation failure.
    """
    path = Path(path)

    if not path.exists():
        raise PolicyLoadError(f"Policy file not found: {path}")

    contents = path.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(contents)
    except yaml.YAMLError as e:
        raise PolicyLoadError(f"Failed to parse YAML: {e}") from e

    if data is None:
        raise PolicyLoadError("Policy file is empty")

    if not isinstance(data, dict):
        raise PolicyLoadError(f"Policy file must be a YAML mapping, got {type(data).__name__}")

    try:
        return PolicyConfig(**data)
    except ValidationError as e:
        lines = ["Policy validation failed:"]
        for err in e.errors():
            loc = ".".join(str(part) for part in err["loc"])
            lines.append(f"  - {loc}: {err['msg']} (got {err['input']!r})")
        raise PolicyLoadError("\n".join(lines)) from e


def compile_regexes(config: PolicyConfig) -> CompiledPolicy:
    """Pre-compile all regex patterns found in policy rules.

    Raises PolicyLoadError if any regex pattern fails to compile.
    """
    regexes: dict[str, re.Pattern] = {}

    for rule in config.policies:
        if isinstance(rule, ParamRule) and rule.check.op == "matches":
            key = f"{rule.name}:check.value"
            try:
                regexes[key] = re.compile(rule.check.value)
            except re.error as e:
                raise PolicyLoadError(
                    f"Rule '{rule.name}' (param_rule): invalid regex in check.value: {e}"
                ) from e

        elif isinstance(rule, ChainRule):
            for i, step in enumerate(rule.steps):
                if step.output_matches is not None:
                    key = f"{rule.name}:steps.{i}.output_matches"
                    try:
                        regexes[key] = re.compile(step.output_matches, re.IGNORECASE)
                    except re.error as e:
                        raise PolicyLoadError(
                            f"Rule '{rule.name}' (chain_rule): "
                            f"invalid regex in steps.{i}.output_matches: {e}"
                        ) from e

                if step.param_matches is not None:
                    for param_name, pattern in step.param_matches.items():
                        key = f"{rule.name}:steps.{i}.param_matches.{param_name}"
                        try:
                            regexes[key] = re.compile(pattern)
                        except re.error as e:
                            raise PolicyLoadError(
                                f"Rule '{rule.name}' (chain_rule): "
                                f"invalid regex in steps.{i}.param_matches.{param_name}: {e}"
                            ) from e

    return CompiledPolicy(config=config, regexes=regexes)


def load_and_compile(path: str | Path) -> CompiledPolicy:
    """Load a policy file and compile all regex patterns.

    Raises PolicyLoadError on any failure.
    """
    config = load_policy(path)
    return compile_regexes(config)
