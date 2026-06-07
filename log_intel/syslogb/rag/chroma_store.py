from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any

import chromadb

from log_intel.syslogb.app import config

logger = logging.getLogger(__name__)

_CHROMA_ADD_BATCH = 200


def _file_hash(path: Path) -> str:
    st = path.stat()
    key = f"{path}:{st.st_mtime_ns}:{st.st_size}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class ChromaStore:
    def __init__(self, persist_dir: Path | None = None) -> None:
        self._dir = persist_dir or config.CHROMA_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=str(self._dir))

    def _collection_name(self, path: Path) -> str:
        return f"job_{_file_hash(path)}"

    def ingest_chunks(
        self,
        path: Path,
        chunks: list[tuple[int, str]],
        embeddings: list[list[float]],
    ) -> str:
        name = self._collection_name(path)
        try:
            self._client.delete_collection(name)
        except Exception:
            pass
        col = self._client.create_collection(name=name, metadata={"source": str(path)})
        ids = [f"c{start}" for start, _ in chunks]
        documents = [text for _, text in chunks]
        metadatas = [{"start_line": start, "source": str(path)} for start, _ in chunks]

        for i in range(0, len(ids), _CHROMA_ADD_BATCH):
            col.add(
                ids=ids[i : i + _CHROMA_ADD_BATCH],
                documents=documents[i : i + _CHROMA_ADD_BATCH],
                embeddings=embeddings[i : i + _CHROMA_ADD_BATCH],
                metadatas=metadatas[i : i + _CHROMA_ADD_BATCH],
            )
        logger.info("Ingested %d chunks into Chroma collection %s", len(chunks), name)
        return name

    def query(self, path: Path, query_embedding: list[float], top_k: int) -> list[dict[str, Any]]:
        name = self._collection_name(path)
        col = self._client.get_collection(name=name)
        n = min(top_k, col.count())
        if n <= 0:
            return []
        res = col.query(query_embeddings=[query_embedding], n_results=n)
        out: list[dict[str, Any]] = []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        for doc, meta, dist in zip(docs, metas, dists):
            out.append({
                "text": doc,
                "start_line": meta.get("start_line", 0) if meta else 0,
                "distance": dist,
            })
        return sorted(out, key=lambda x: x.get("start_line", 0))
