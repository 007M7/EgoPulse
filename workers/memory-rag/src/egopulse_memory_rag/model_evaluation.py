from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import asdict
import json
import os
from pathlib import Path
from time import perf_counter
from typing import Any, Sequence

from .evaluation import evaluate_lexical_dataset, evaluate_retriever, load_dataset
from .experimental import ExactVectorRetriever, ReciprocalRankFusionRetriever
from .fastembed_provider import FastEmbedProvider, SUPPORTED_MODEL_SPECS
from .retrieval import ALGORITHM_ID, retrieve


def evaluate_model(
    *,
    dataset_path: Path,
    model_alias: str,
    cache_dir: Path,
    threads: int,
    k: int,
    lexical_weight: float,
    semantic_weight: float,
    local_files_only: bool,
) -> dict[str, Any]:
    spec = SUPPORTED_MODEL_SPECS[model_alias]
    startup_started = perf_counter()
    provider = FastEmbedProvider(
        spec,
        cache_dir=cache_dir,
        threads=threads,
        local_files_only=local_files_only,
    )
    startup_ms = _milliseconds_since(startup_started)

    semantic = ExactVectorRetriever(provider.profile, provider)
    hybrid = ReciprocalRankFusionRetriever(
        left=retrieve,
        left_algorithm_id=ALGORITHM_ID,
        right=semantic,
        right_algorithm_id=semantic.algorithm_id,
        left_weight=lexical_weight,
        right_weight=semantic_weight,
    )
    dataset_id, dataset_sha256, cases = load_dataset(dataset_path)

    lexical_started = perf_counter()
    lexical_report = evaluate_lexical_dataset(dataset_path, k=k)
    lexical_ms = _milliseconds_since(lexical_started)

    semantic_started = perf_counter()
    semantic_report = evaluate_retriever(
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        algorithm_id=semantic.algorithm_id,
        cases=cases,
        retriever=semantic,
        k=k,
    )
    semantic_ms = _milliseconds_since(semantic_started)

    hybrid_started = perf_counter()
    hybrid_report = evaluate_retriever(
        dataset_id=dataset_id,
        dataset_sha256=dataset_sha256,
        algorithm_id=hybrid.algorithm_id,
        cases=cases,
        retriever=hybrid,
        k=k,
    )
    hybrid_ms = _milliseconds_since(hybrid_started)

    return {
        "dataset_id": dataset_id,
        "dataset_sha256": dataset_sha256,
        "k": k,
        "fusion": {
            "lexical_weight": lexical_weight,
            "rank_constant": hybrid.rank_constant,
            "semantic_weight": semantic_weight,
        },
        "model": {
            "alias": spec.alias,
            "artifact_bytes": provider.model_artifact_bytes,
            "artifact_sha256": provider.model_artifact_sha256,
            "license": provider.license,
            "profile": asdict(provider.profile),
            "snapshot_artifact_bytes": provider.snapshot_artifact_bytes,
            "snapshot_revision": provider.snapshot_revision,
        },
        "process": _process_memory(),
        "reports": {
            "hybrid": json.loads(hybrid_report.to_json()),
            "lexical": json.loads(lexical_report.to_json()),
            "semantic": json.loads(semantic_report.to_json()),
        },
        "timing_ms": {
            "hybrid_evaluation": hybrid_ms,
            "lexical_evaluation": lexical_ms,
            "model_initialization_and_digest": startup_ms,
            "semantic_evaluation": semantic_ms,
        },
    }


def _milliseconds_since(started: float) -> float:
    return round((perf_counter() - started) * 1000.0, 3)


def _process_memory() -> dict[str, int] | None:
    if os.name != "nt":
        return None

    class ProcessMemoryCountersEx(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(ProcessMemoryCountersEx)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    process = kernel32.GetCurrentProcess()
    success = psapi.GetProcessMemoryInfo(
        process,
        ctypes.byref(counters),
        counters.cb,
    )
    if not success:
        return None
    return {
        "peak_working_set_bytes": int(counters.PeakWorkingSetSize),
        "private_usage_bytes": int(counters.PrivateUsage),
        "working_set_bytes": int(counters.WorkingSetSize),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate one pinned FastEmbed candidate behind the EgoPulse gate"
    )
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument(
        "--model",
        required=True,
        choices=sorted(SUPPORTED_MODEL_SPECS),
    )
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--k", type=int, default=2)
    parser.add_argument("--lexical-weight", type=float, default=1.0)
    parser.add_argument("--semantic-weight", type=float, default=1.0)
    parser.add_argument("--local-files-only", action="store_true")
    arguments = parser.parse_args(argv)
    report = evaluate_model(
        dataset_path=arguments.dataset,
        model_alias=arguments.model,
        cache_dir=arguments.cache_dir,
        threads=arguments.threads,
        k=arguments.k,
        lexical_weight=arguments.lexical_weight,
        semantic_weight=arguments.semantic_weight,
        local_files_only=arguments.local_files_only,
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
