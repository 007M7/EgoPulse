from __future__ import annotations

from dataclasses import asdict

from egopulse_memory_rag.admission import (
    ROLLBACK_ALGORITHM_ID,
    evaluate_candidate_gate,
)
from egopulse_memory_rag.evaluation import evaluate_lexical_dataset


DATASET_SHA256 = "a" * 64


def report(algorithm_id: str = "semantic-v0", *, metric: float = 1.0) -> dict[str, object]:
    return {
        "dataset_id": "dataset-v0",
        "dataset_sha256": DATASET_SHA256,
        "algorithm_id": algorithm_id,
        "case_count": 2,
        "k": 2,
        "recall_at_k": metric,
        "mean_reciprocal_rank": metric,
        "ndcg_at_k": metric,
        "cases": [],
    }


def package(*, metric: float = 1.0, deterministic: bool = True) -> dict[str, object]:
    return {
        "deterministic_replay": deterministic,
        "reports": {"hybrid": report(metric=metric)},
        "model": {
            "artifact_bytes": 10,
            "artifact_sha256": "b" * 64,
            "snapshot_artifact_bytes": 20,
            "snapshot_revision": "snapshot-v0",
        },
        "timing_ms": {
            "model_initialization_and_digest": 1.0,
            "lexical_evaluation": 1.0,
            "semantic_evaluation": 1.0,
            "hybrid_evaluation": 1.0,
        },
        "process": {"private_usage_bytes": 100},
    }


def test_candidate_pass_is_opt_in_only_and_has_lexical_rollback() -> None:
    decision = evaluate_candidate_gate(
        baseline=report(ROLLBACK_ALGORITHM_ID), candidate_package=package()
    )

    assert decision.eligible_for_opt_in is True
    assert decision.default_route_changed is False
    assert decision.rollback_algorithm_id == ROLLBACK_ALGORITHM_ID
    assert decision.reasons == ()


def test_quality_regression_is_rejected_with_a_rollback_target() -> None:
    decision = evaluate_candidate_gate(
        baseline=report(ROLLBACK_ALGORITHM_ID), candidate_package=package(metric=0.9)
    )

    assert decision.eligible_for_opt_in is False
    assert "quality_regression:recall_at_k" in decision.reasons
    assert decision.rollback_algorithm_id == ROLLBACK_ALGORITHM_ID


def test_missing_provenance_or_replay_attestation_fails_closed() -> None:
    candidate = package(deterministic=False)
    candidate["model"] = {}

    decision = evaluate_candidate_gate(baseline=report(ROLLBACK_ALGORITHM_ID), candidate_package=candidate)

    assert decision.eligible_for_opt_in is False
    assert "deterministic_replay_not_attested" in decision.reasons
    assert "model_artifact_bytes_missing" in decision.reasons
    assert "model_artifact_sha256_missing_or_invalid" in decision.reasons


def test_real_project_baseline_can_be_used_as_gate_input() -> None:
    baseline = evaluate_lexical_dataset(
        __import__("pathlib").Path(__file__).parents[1]
        / "evaluation"
        / "project-boundaries-v0.json",
        k=2,
    )
    candidate = {
        **package(),
        "reports": {
            "hybrid": {
                **asdict(baseline),
                "algorithm_id": "semantic-v0",
            }
        },
    }

    decision = evaluate_candidate_gate(baseline=baseline, candidate_package=candidate)

    assert decision.eligible_for_opt_in is True
    assert decision.dataset_sha256 == baseline.dataset_sha256


def test_metric_outside_probability_range_is_rejected_before_admission() -> None:
    invalid_baseline = report(metric=1.1)

    try:
        evaluate_candidate_gate(baseline=invalid_baseline, candidate_package=package())
    except ValueError as error:
        assert "outside the [0, 1] range" in str(error)
    else:
        raise AssertionError("out-of-range evaluation metrics must fail closed")


def test_partial_timing_provenance_is_rejected() -> None:
    candidate = package()
    candidate["timing_ms"] = {
        "model_initialization_and_digest": 1.0,
        "lexical_evaluation": 1.0,
        "semantic_evaluation": None,
        "hybrid_evaluation": 1.0,
    }

    decision = evaluate_candidate_gate(baseline=report(ROLLBACK_ALGORITHM_ID), candidate_package=candidate)

    assert decision.eligible_for_opt_in is False
    assert "semantic_evaluation_timing_missing_or_invalid" in decision.reasons
