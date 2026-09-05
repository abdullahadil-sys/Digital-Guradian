"""
Digital Guardian - RAG Orchestration

This module wires together the three distinct stages of the pipeline
and MUST keep them clearly separated:

  1. RETRIEVAL   -> RetrievalService fetches trusted scam-pattern
                     entries relevant to the user's message.
  2. AUGMENTATION -> The retrieved entries are formatted into grounded
                     context for the generation stage.
  3. GENERATION   -> LLMService (or its heuristic fallback) produces
                     the final structured risk analysis, which is then
                     independently validated/clamped — the pipeline
                     never blindly trusts the generation stage.

The public entry point is `RAGPipeline.analyze(message)`.
"""

import logging
from typing import List

from app.config import Settings
from app.schemas import AnalyzeResponse, RetrievedSource
from app.services.llm_service import LLMService
from app.services.retrieval_service import RetrievalError, RetrievalService

logger = logging.getLogger("digital_guardian.rag")


class RAGPipelineError(Exception):
    """Raised when the pipeline cannot produce any analysis at all."""


class RAGPipeline:
    def __init__(self, settings: Settings):
        self._settings = settings
        try:
            self._retrieval_service = RetrievalService()
        except RetrievalError as exc:
            logger.exception("Failed to initialize retrieval service")
            raise RAGPipelineError(str(exc)) from exc

        self._llm_service = LLMService(settings)

    @property
    def knowledge_base_entries(self) -> int:
        return self._retrieval_service.entry_count

    def analyze(self, message: str) -> AnalyzeResponse:
        # ---------- 1. RETRIEVAL ----------
        try:
            sources: List[RetrievedSource] = self._retrieval_service.retrieve(
                message, top_k=self._settings.retrieval_top_k
            )
        except RetrievalError as exc:
            logger.exception("Retrieval stage failed")
            # Retrieval failing should not take the whole assistant offline —
            # continue with an empty context so generation can still fall back safely.
            sources = []
            logger.warning("Continuing analysis with empty retrieval context: %s", exc)

        retrieved_indicators = self._retrieval_service.get_indicators_for_sources(sources) if sources else []

        # ---------- 2. AUGMENTATION ----------
        augmented_context = [
            {"category": s.category, "title": s.title, "summary": s.summary} for s in sources
        ]

        # ---------- 3. GENERATION ----------
        result = self._llm_service.generate_analysis(
            message=message,
            retrieved_context=augmented_context,
            retrieved_indicators=retrieved_indicators,
        )

        return AnalyzeResponse(
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            verdict=result.verdict,
            explanation=result.explanation,
            red_flags=result.red_flags,
            safe_actions=result.safe_actions,
            sources=sources,
            analysis_mode=result.mode,
            uncertainty_note=result.uncertainty_note,
        )
