from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from math import isfinite
from typing import Any, Mapping

from .evaluation import EvaluationReport
from .retrieval import ALGORITHM_ID


ROLLBACK_ALGORITHM_ID = ALGORITHM_ID
_METRICS = ("recall_at_k", "mean_reciprocal_rank", "ndcg_at_k")


class EvaluationAdmissionError(ValueError):
    """The candidate evaluation package is incomplete or unsafe to admit."""


@dataclass(frozen=True, slots=True)
class EvaluationGateLimits:
    """Resource and quality limits for an opt-in retrieval candidate.

    These limits govern an experimental Worker candidate. They do not change
    the Rust Memory Authority or the default lexical route.
    """

    max_model_artifact_bytes: int = 2 * 1024 * 1024 * 1024
    max_snapshot_artifact_bytes: int = 4 * 1024 * 1024 * 1024
    max_initialization_ms: float = 120_000.0
    max_evaluation_ms: float = 300_000.0
    max_private_usage_bytes: int = 2 * 1024 * 1024 * 1024
    metric_tolerance: float = 1e-8

    def validate(self) -> None:
        integer_limits = (
            self.max_model_artifact_bytes,
            self.max_snapshot_artifact_bytes,
            self.max_private_usage_bytes,
        )
        if any(value <= 0 for value in integer_limits):
            raise EvaluationAdmissionError("resource limits must be positive")
        float_limits = (
            self.max_initialization_ms,
            self.max_evaluation_ms,
            self.metric_tolerance,
        )
        if any(not isfinite(value) or value < 0.0 for value in float_limits):
            raise EvaluationAdmissionError("numeric limits must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class EvaluationGateDecision:
    candidate_kind: str
    candidate_algorithm_id: str
    rollback_algorithm_id: str
    dataset_id: str
    dataset_sha256: str
    eligible_for_opt_in: bool
    default_route_changed: bool
    reasons: tuple[str, ...]
    quality: dict[str, dict[str, float]]
    provenance: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


def evaluate_candidate_gate(
    *,
    baseline: EvaluationReport | Mapping[str, Any],
    candidate_package: Mapping[str, Any],
    candidate_report_name: str = "hybrid",
    candidate_kind: str = "semantic-or-hybrid",
    limits: EvaluationGateLimits | None = None,
) -> EvaluationGateDecision:
    """Return a fail-closed, rollback-ready decision for one candidate.

    The candidate must match the exact corpus and preserve every baseline
    metric within tolerance. A quality pass is necessary but not sufficient
    for production: this decision only grants *opt-in eligibility*. The
    default route is explicitly reported as unchanged and rollback always
    points to ``lexical-overlap-v0``.
    """

    active_limits = limits or EvaluationGateLimits()
    active_limits.validate()
    if not candidate_kind.strip():
        raise EvaluationAdmissionError("candidate kind is required")

    baseline_values = _report_values(baseline, "baseline")
    candidate_reports = candidate_package.get("reports")
    if not isinstance(candidate_reports, Mapping):
        raise EvaluationAdmissionError("candidate reports are required")
    candidate = candidate_reports.get(candidate_report_name)
    if not isinstance(candidate, Mapping):
        raise EvaluationAdmissionError(
            f"candidate report {candidate_report_name!r} is required"
        )
    candidate_values = _report_values(candidate, "candidate")

    reasons: list[str] = []
    if candidate_values["dataset_id"] != baseline_values["dataset_id"]:
        reasons.append("dataset_id_mismatch")
    if candidate_values["dataset_sha256"] != baseline_values["dataset_sha256"]:
        reasons.append("dataset_sha256_mismatch")
    if candidate_values["case_count"] != baseline_values["case_count"]:
        reasons.append("case_count_mismatch")
    if candidate_values["k"] != baseline_values["k"]:
        reasons.append("evaluation_k_mismatch")

    quality: dict[str, dict[str, float]] = {}
    for metric in _METRICS:
        before = baseline_values[metric]
        after = candidate_values[metric]
        quality[metric] = {"baseline": before, "candidate": after, "delta": after - before}
        if after + active_limits.metric_tolerance < before:
            reasons.append(f"quality_regression:{metric}")

    if candidate_values["algorithm_id"] == ROLLBACK_ALGORITHM_ID:
        reasons.append("candidate_algorithm_is_rollback_target")
    if candidate_package.get("deterministic_replay") is not True:
        reasons.append("deterministic_replay_not_attested")

    model = candidate_package.get("model")
    if not isinstance(model, Mapping):
        reasons.append("model_provenance_missing")
        model = {}
    _check_positive_integer(model.get("artifact_bytes"), "model_artifact_bytes", reasons)
    _check_sha256(model.get("artifact_sha256"), "model_artifact_sha256", reasons)
    _check_positive_integer(
        model.get("snapshot_artifact_bytes"), "snapshot_artifact_bytes", reasons
    )
    if not _is_text(model.get("snapshot_revision")):
        reasons.append("snapshot_revision_missing")

    artifact_bytes = _integer_or_zero(model.get("artifact_bytes"))
    snapshot_bytes = _integer_or_zero(model.get("snapshot_artifact_bytes"))
    if artifact_bytes > active_limits.max_model_artifact_bytes:
        reasons.append("model_artifact_budget_exceeded")
    if snapshot_bytes > active_limits.max_snapshot_artifact_bytes:
        reasons.append("snapshot_artifact_budget_exceeded")

    timing = candidate_package.get("timing_ms")
    if not isinstance(timing, Mapping):
        reasons.append("timing_provenance_missing")
        timing = {}
    initialization_ms = _finite_number(timing.get("model_initialization_and_digest"))
    if initialization_ms is None:
        reasons.append("initialization_timing_missing")
    elif initialization_ms > active_limits.max_initialization_ms:
        reasons.append("initialization_budget_exceeded")
    evaluation_ms = sum(
        value
        for value in (
            _finite_number(timing.get("lexical_evaluation")),
            _finite_number(timing.get("semantic_evaluation")),
            _finite_number(timing.get("hybrid_evaluation")),
        )
        if value is not None
    )
    if evaluation_ms == 0.0:
        reasons.append("evaluation_timing_missing")
    elif evaluation_ms > active_limits.max_evaluation_ms:
        reasons.append("evaluation_budget_exceeded")

    process = candidate_package.get("process")
    if isinstance(process, Mapping):
        private_usage = _integer_or_zero(process.get("private_usage_bytes"))
        if private_usage > active_limits.max_private_usage_bytes:
            reasons.append("private_memory_budget_exceeded")

    provenance = {
        "model": dict(model),
        "process": dict(process) if isinstance(process, Mapping) else None,
        "timing_ms": dict(timing),
    }
    return EvaluationGateDecision(
        candidate_kind=candidate_kind,
        candidate_algorithm_id=str(candidate_values["algorithm_id"]),
        rollback_algorithm_id=ROLLBACK_ALGORITHM_ID,
        dataset_id=str(candidate_values["dataset_id"]),
        dataset_sha256=str(candidate_values["dataset_sha256"]),
        eligible_for_opt_in=not reasons,
        default_route_changed=False,
        reasons=tuple(reasons),
        quality=quality,
        provenance=provenance,
    )


def _report_values(report: EvaluationReport | Mapping[str, Any], label: str) -> dict[str, Any]:
    if isinstance(report, EvaluationReport):
        values = asdict(report)
    elif isinstance(report, Mapping):
        values = dict(report)
    else:
        raise EvaluationAdmissionError(f"{label} report is invalid")
    required = ("dataset_id", "dataset_sha256", "algorithm_id", "case_count", "k", *_METRICS)
    if any(field not in values for field in required):
        raise EvaluationAdmissionError(f"{label} report is incomplete")
    if not _is_text(values["dataset_id"]) or not _is_text(values["algorithm_id"]):
        raise EvaluationAdmissionError(f"{label} report identity is invalid")
    if not _is_sha256(values["dataset_sha256"]):
        raise EvaluationAdmissionError(f"{label} dataset digest is invalid")
    if not isinstance(values["case_count"], int) or values["case_count"] <= 0:
        raise EvaluationAdmissionError(f"{label} case count is invalid")
    if not isinstance(values["k"], int) or values["k"] <= 0:
        raise EvaluationAdmissionError(f"{label} k is invalid")
    for metric in _METRICS:
        if _finite_number(values[metric]) is None:
            raise EvaluationAdmissionError(f"{label} metric {metric} is invalid")
    return values


def _check_positive_integer(value: Any, name: str, reasons: list[str]) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        reasons.append(f"{name}_missing")


def _integer_or_zero(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if isfinite(number) and number >= 0.0 else None


def _check_sha256(value: Any, name: str, reasons: list[str]) -> None:
    if not isinstance(value, str) or not _is_sha256(value):
        reasons.append(f"{name}_missing_or_invalid")


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
