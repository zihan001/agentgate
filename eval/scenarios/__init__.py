"""Evaluation scenarios — 10 benign + 15 adversarial test vectors."""

from eval.scenarios.adversarial import ADVERSARIAL_SCENARIOS
from eval.scenarios.benign import BENIGN_SCENARIOS

ALL_SCENARIOS = BENIGN_SCENARIOS + ADVERSARIAL_SCENARIOS
