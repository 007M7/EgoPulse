from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from importlib.metadata import version
import os
from pathlib import Path
from typing import Any

from .experimental import EmbeddingProfile
from .retrieval import RetrievalWorkerError


@dataclass(frozen=True, slots=True)
class FastEmbedModelSpec:
    alias: str
    model_name: str
    dimensions: int
    preprocessing: str
    query_prefix: str
    document_prefix: str
    expected_model_sha256: str
    license: str
    custom_hf_repo: str | None
    model_file: str
    additional_files: tuple[str, ...]

    def validate(self) -> None:
        for field, value in (
            ("alias", self.alias),
            ("model_name", self.model_name),
            ("preprocessing", self.preprocessing),
            ("expected_model_sha256", self.expected_model_sha256),
            ("license", self.license),
        ):
            if not value.strip():
                raise RetrievalWorkerError(f"FastEmbed {field} is required")
        if not 1 <= self.dimensions <= 65_536:
            raise RetrievalWorkerError("FastEmbed dimensions are outside the worker limit")
        if not _is_sha256(self.expected_model_sha256):
            raise RetrievalWorkerError("FastEmbed model digest is invalid")


PARAPHRASE_MULTILINGUAL_MINILM_V0 = FastEmbedModelSpec(
    alias="paraphrase-multilingual-minilm-v0",
    model_name="sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2",
    dimensions=384,
    preprocessing="symmetric-raw-mean-pooling-v0",
    query_prefix="",
    document_prefix="",
    expected_model_sha256=(
        "634d0f66c29dc934c8fa72b8a4fe91dd4d420a22f1d82a241058d4316e659a99"
    ),
    license="Apache-2.0",
    custom_hf_repo=None,
    model_file="model_optimized.onnx",
    additional_files=(),
)

MULTILINGUAL_E5_SMALL_V0 = FastEmbedModelSpec(
    alias="multilingual-e5-small-v0",
    model_name="intfloat/multilingual-e5-small",
    dimensions=384,
    preprocessing="e5-query-passage-prefix-mean-pooling-v0",
    query_prefix="query: ",
    document_prefix="passage: ",
    expected_model_sha256=(
        "ca456c06b3a9505ddfd9131408916dd79290368331e7d76bb621f1cba6bc8665"
    ),
    license="MIT",
    custom_hf_repo="intfloat/multilingual-e5-small",
    model_file="onnx/model.onnx",
    additional_files=("tokenizer.json",),
)

SUPPORTED_MODEL_SPECS = {
    PARAPHRASE_MULTILINGUAL_MINILM_V0.alias: PARAPHRASE_MULTILINGUAL_MINILM_V0,
    MULTILINGUAL_E5_SMALL_V0.alias: MULTILINGUAL_E5_SMALL_V0,
}


class FastEmbedProvider:
    """Pinned, CPU-only FastEmbed adapter for offline candidate evaluation."""

    def __init__(
        self,
        spec: FastEmbedModelSpec,
        *,
        cache_dir: Path,
        threads: int,
        local_files_only: bool = False,
    ) -> None:
        spec.validate()
        if not 1 <= threads <= 256:
            raise RetrievalWorkerError("FastEmbed thread count is outside the worker limit")
        try:
            from fastembed import TextEmbedding

            if spec.custom_hf_repo is not None and not any(
                value["model"] == spec.model_name
                for value in TextEmbedding.list_supported_models()
            ):
                from fastembed.common.model_description import ModelSource, PoolingType

                TextEmbedding.add_custom_model(
                    model=spec.model_name,
                    pooling=PoolingType.MEAN,
                    normalization=True,
                    sources=ModelSource(hf=spec.custom_hf_repo),
                    dim=spec.dimensions,
                    model_file=spec.model_file,
                    description="Pinned EgoPulse evaluation candidate",
                    license=spec.license,
                    size_in_gb=0.5,
                    additional_files=list(spec.additional_files),
                )

            model = TextEmbedding(
                model_name=spec.model_name,
                cache_dir=str(cache_dir),
                threads=threads,
                providers=["CPUExecutionProvider"],
                local_files_only=local_files_only,
            )
        except Exception as error:
            raise RetrievalWorkerError("FastEmbed model initialization failed") from error

        if model.embedding_size != spec.dimensions:
            raise RetrievalWorkerError("FastEmbed model dimensions drifted")
        model_dir = Path(_required_runtime_value(model.model, "_model_dir"))
        description = _required_runtime_value(model.model, "model_description")
        model_file = model_dir / _required_runtime_value(description, "model_file")
        if not model_file.is_file():
            raise RetrievalWorkerError("FastEmbed model artifact is missing")
        model_sha256 = _file_sha256(model_file)
        if model_sha256 != spec.expected_model_sha256:
            raise RetrievalWorkerError("FastEmbed model artifact digest drifted")

        self._spec = spec
        self._model = model
        self._model_file = model_file
        self._snapshot_artifact_bytes = _snapshot_file_bytes(model_dir)
        self._model_sha256 = model_sha256
        self._snapshot_revision = model_dir.name
        self._runtime_identity = (
            f"fastembed=={version('fastembed')};onnxruntime=={version('onnxruntime')}"
        )

    @property
    def profile(self) -> EmbeddingProfile:
        return EmbeddingProfile(
            provider=self._runtime_identity,
            model=self._spec.model_name,
            revision=(
                f"hf-snapshot:{self._snapshot_revision};"
                f"onnx-sha256:{self._model_sha256}"
            ),
            preprocessing=self._spec.preprocessing,
            dimensions=self._spec.dimensions,
        )

    @property
    def model_artifact_bytes(self) -> int:
        return self._model_file.stat().st_size

    @property
    def model_artifact_sha256(self) -> str:
        return self._model_sha256

    @property
    def snapshot_artifact_bytes(self) -> int:
        return self._snapshot_artifact_bytes

    @property
    def snapshot_revision(self) -> str:
        return self._snapshot_revision

    @property
    def license(self) -> str:
        return self._spec.license

    def embed_query(self, text: str) -> Sequence[float]:
        return self._embed_one(self._spec.query_prefix + text)

    def embed_documents(self, texts: Sequence[str]) -> Sequence[Sequence[float]]:
        if not texts:
            return ()
        try:
            vectors = tuple(
                self._model.embed(
                    [self._spec.document_prefix + text for text in texts],
                    batch_size=min(64, len(texts)),
                    parallel=None,
                )
            )
        except Exception as error:
            raise RetrievalWorkerError("FastEmbed document inference failed") from error
        return tuple(vector.tolist() for vector in vectors)

    def _embed_one(self, text: str) -> Sequence[float]:
        try:
            vectors = tuple(self._model.embed([text], batch_size=1, parallel=None))
        except Exception as error:
            raise RetrievalWorkerError("FastEmbed query inference failed") from error
        if len(vectors) != 1:
            raise RetrievalWorkerError("FastEmbed query vector count drifted")
        return vectors[0].tolist()


def _required_runtime_value(value: Any, field: str) -> Any:
    result = getattr(value, field, None)
    if result is None:
        raise RetrievalWorkerError(f"FastEmbed runtime field {field} is missing")
    return result


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot_file_bytes(path: Path) -> int:
    total = 0
    for root, directories, files in os.walk(path, onerror=lambda error: None):
        directories[:] = [value for value in directories if not value.startswith("tmp")]
        for filename in files:
            try:
                total += (Path(root) / filename).stat().st_size
            except OSError:
                continue
    return total


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
