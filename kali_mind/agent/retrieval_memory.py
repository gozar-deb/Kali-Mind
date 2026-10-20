"""Long-context memory via simple lexical retrieval (no embedding dependency).

Chunks session notes + tool summaries and retrieves top-k relevant snippets
for the current query. Optional: if ``sentence-transformers`` is installed,
uses embeddings automatically.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import List, Tuple

logger = logging.getLogger(__name__)

_TOKEN = re.compile(r"[a-z0-9_./:-]+", re.I)


def _tokenize(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN.findall(text or "") if len(t) > 1]


class RetrievalMemory:
    def __init__(self) -> None:
        self._chunks: List[str] = []
        self._embedder = None
        self._vectors: list = []
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
            self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
            logger.debug("Embedding backend enabled")
        except Exception:
            pass

    def add(self, text: str) -> None:
        text = (text or "").strip()
        if not text:
            return
        # Split long text into ~500-char chunks
        for i in range(0, len(text), 500):
            chunk = text[i:i + 500]
            self._chunks.append(chunk)
            if self._embedder is not None:
                try:
                    self._vectors.append(self._embedder.encode(chunk))
                except Exception:
                    self._vectors.append(None)

    def retrieve(self, query: str, k: int = 5) -> List[str]:
        if not self._chunks:
            return []
        if self._embedder is not None and self._vectors:
            return self._retrieve_embed(query, k)
        return self._retrieve_lexical(query, k)

    def _retrieve_lexical(self, query: str, k: int) -> List[str]:
        q = Counter(_tokenize(query))
        if not q:
            return self._chunks[-k:]
        scored: List[Tuple[float, str]] = []
        for chunk in self._chunks:
            tf = Counter(_tokenize(chunk))
            score = sum(tf[t] * q[t] for t in q)
            # length normalize
            score = score / math.sqrt(len(tf) + 1)
            if score > 0:
                scored.append((score, chunk))
        scored.sort(key=lambda x: -x[0])
        return [c for _, c in scored[:k]]

    def _retrieve_embed(self, query: str, k: int) -> List[str]:
        try:
            import numpy as np
            qv = self._embedder.encode(query)
            scored = []
            for chunk, vec in zip(self._chunks, self._vectors):
                if vec is None:
                    continue
                sim = float(np.dot(qv, vec) / (np.linalg.norm(qv) * np.linalg.norm(vec) + 1e-9))
                scored.append((sim, chunk))
            scored.sort(key=lambda x: -x[0])
            return [c for _, c in scored[:k]]
        except Exception as e:
            logger.debug("embed retrieve failed: %s", e)
            return self._retrieve_lexical(query, k)

    def context_block(self, query: str, k: int = 5) -> str:
        hits = self.retrieve(query, k=k)
        if not hits:
            return ""
        return "Retrieved context:\n" + "\n---\n".join(hits)
