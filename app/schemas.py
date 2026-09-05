"""
Digital Guardian - Pydantic Schemas

Defines the request/response contracts for the API layer, plus internal
data models used by the RAG pipeline. Keeping these in one module makes
the contract easy to audit and keeps FastAPI's auto-generated docs
(/docs) accurate.
"""

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description="The suspicious email, SMS, social media message, or link text to analyze.",
    )

    @field_validator("message")
    @classmethod
    def message_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message cannot be empty or whitespace only")
        return value.strip()


class RetrievedSource(BaseModel):
    id: str
    category: str
    title: str
    summary: str
    relevance: float = Field(..., ge=0.0, le=1.0)


class AnalyzeResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    verdict: str
    explanation: str
    red_flags: List[str]
    safe_actions: List[str]
    sources: List[RetrievedSource]
    analysis_mode: str = Field(
        ..., description="Either 'llm' when an LLM provider generated the analysis, or 'heuristic' fallback."
    )
    uncertainty_note: Optional[str] = Field(
        default=None,
        description="Populated when the evidence is inconclusive and the assistant cannot commit to a firm verdict.",
    )


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str
    llm_enabled: bool
    llm_provider: str
    knowledge_base_entries: int


class ErrorResponse(BaseModel):
    error: str
    detail: str
