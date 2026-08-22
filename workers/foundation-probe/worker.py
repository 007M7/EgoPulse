from __future__ import annotations

import json
from typing import Literal, TypedDict


class WorkerHealth(TypedDict):
    worker: Literal["foundation-probe"]
    status: Literal["foundation-only"]


def health() -> WorkerHealth:
    return {"worker": "foundation-probe", "status": "foundation-only"}


if __name__ == "__main__":
    print(json.dumps(health(), separators=(",", ":")))
