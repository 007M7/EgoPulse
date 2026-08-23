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
    if len(modules) != 9:
        raise RuntimeError(f"expected 9 generated Python modules, found {len(modules)}: {modules}")
    print(f"python_generated_imports=passed modules={len(modules)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
