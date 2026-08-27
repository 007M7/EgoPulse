from __future__ import annotations

import importlib
import pathlib
import sys


def main() -> int:
    generated_root = pathlib.Path(__file__).resolve().parents[1] / "generated" / "python"
    sys.path.insert(0, str(generated_root))
    modules = []
    for source in sorted(generated_root.rglob("*_pb2.py")):
        relative = source.relative_to(generated_root).with_suffix("")
        module_name = ".".join(relative.parts)
        importlib.import_module(module_name)
        modules.append(module_name)
    expected_modules = {
        "egopulse.artifact.v1.artifact_pb2",
        "egopulse.collaboration.v1.collaboration_pb2",
        "egopulse.common.v1.common_pb2",
        "egopulse.foundation.v1.health_pb2",
        "egopulse.harness.v1.harness_pb2",
        "egopulse.localapi.v1.local_api_pb2",
        "egopulse.persistence.v1.persistence_pb2",
        "egopulse.policy.v1.policy_pb2",
        "egopulse.task.v1.task_pb2",
        "egopulse.verdict.v1.verdict_pb2",
        "egopulse.verification.v1.verification_pb2",
    }
    if set(modules) != expected_modules:
        raise RuntimeError(
            f"expected the 10 V-01 modules plus Foundation, found {len(modules)}: {modules}"
        )
    print(f"python_generated_imports=passed modules={len(modules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
