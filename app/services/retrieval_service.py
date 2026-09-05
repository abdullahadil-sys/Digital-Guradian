"""
Digital Guardian - Retrieval Service

Loads the trusted scam-pattern knowledge base from disk and exposes a
`retrieve(query, top_k)` method that returns the most relevant entries
using the EmbeddingService's vector-space similarity. This is the
"R" (Retrieval) stage of the RAG pipeline and is fully decoupled from
both the LLM and the API layer.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

from app.schemas import RetrievedSource
from app.services.embedding_service import EmbeddingService

logger = logging.getLogger("digital_guardian.retrieval")

KNOWLEDGE_BASE_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "knowledge_base.json"


class RetrievalError(Exception):
    """Raised when the knowledge base cannot be loaded or searched."""


class RetrievalService:
    def __init__(self, knowledge_base_path: Path = KNOWLEDGE_BASE_PATH):
        self._entries: List[Dict] = self._load_knowledge_base(knowledge_base_path)
        corpus = [self._entry_to_text(entry) for entry in self._entries]
        self._embedding_service = EmbeddingService(corpus=corpus)

    @staticmethod
    def _load_knowledge_base(path: Path) -> List[Dict]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list) or not data:
                raise RetrievalError("Knowledge base file is empty or malformed.")
            return data
        except FileNotFoundError as exc:
            raise RetrievalError(f"Knowledge base file not found at {path}") from exc
        except json.JSONDecodeError as exc:
            raise RetrievalError(f"Knowledge base file at {path} contains invalid JSON.") from exc

    @staticmethod
    def _entry_to_text(entry: Dict) -> str:
        indicators = " ".join(entry.get("indicators", []))
        return f"{entry.get('title', '')} {entry.get('summary', '')} {indicators}"

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def retrieve(self, query: str, top_k: int = 4) -> List[RetrievedSource]:
        """
        Retrieve the top_k most relevant knowledge-base entries for a query,
        ranked by cosine similarity in TF-IDF vector space.
        """
        if not self._entries:
            raise RetrievalError("Knowledge base is empty; cannot retrieve.")

        try:
            scores = self._embedding_service.similarity_to_corpus(query)
        except Exception as exc:  # noqa: BLE001 - convert any vectorization failure into a domain error
            logger.exception("Embedding similarity computation failed")
            raise RetrievalError("Failed to compute retrieval similarity scores.") from exc

        ranked_indices = scores.argsort()[::-1][:top_k]

        results: List[RetrievedSource] = []
        for idx in ranked_indices:
            entry = self._entries[int(idx)]
            relevance = float(scores[int(idx)])
            # Only surface entries with non-trivial relevance; pure noise matches are dropped.
            if relevance <= 0.0:
                continue
            results.append(
                RetrievedSource(
                    id=entry["id"],
                    category=entry["category"],
                    title=entry["title"],
                    summary=entry["summary"],
                    relevance=round(min(relevance, 1.0), 4),
                )
            )
        return results

    def get_indicators_for_sources(self, sources: List[RetrievedSource]) -> List[str]:
        """Collect the raw 'indicators' lists for a set of retrieved sources, for use in augmentation."""
        source_ids = {s.id for s in sources}
        indicators: List[str] = []
        for entry in self._entries:
            if entry["id"] in source_ids:
                indicators.extend(entry.get("indicators", []))
        return indicators
