from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .admission import evaluate_candidate_gate
from .evaluation import evaluate_lexical_dataset
from .model_evaluation import evaluate_model
from .fastembed_provider import SUPPORTED_MODEL_SPECS


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a pinned Memory/RAG candidate and the fail-closed production gate"
    )
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--model", required=True, choices=sorted(SUPPORTED_MODEL_SPECS))
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--k", type=int, default=2)
    parser.add_argument("--lexical-weight", type=float, default=1.0)
    parser.add_argument("--semantic-weight", type=float, default=1.0)
    parser.add_argument("--local-files-only", action="store_true")
    arguments = parser.parse_args(argv)

    baseline = evaluate_lexical_dataset(arguments.dataset, k=arguments.k)
    candidate_package = evaluate_model(
        dataset_path=arguments.dataset,
        model_alias=arguments.model,
        cache_dir=arguments.cache_dir,
        threads=arguments.threads,
        k=arguments.k,
        lexical_weight=arguments.lexical_weight,
        semantic_weight=arguments.semantic_weight,
        local_files_only=arguments.local_files_only,
    )
    decision = evaluate_candidate_gate(
        baseline=baseline,
        candidate_package=candidate_package,
    )
    evidence = {
        "baseline": json.loads(baseline.to_json()),
        "candidate": candidate_package,
        "gate": json.loads(decision.to_json()),
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(evidence, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    print(decision.to_json())
    return 0 if decision.eligible_for_opt_in else 2


if __name__ == "__main__":
    raise SystemExit(main())
