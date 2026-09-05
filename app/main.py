"""
Digital Guardian - FastAPI Application Entry Point

Exposes:
  GET  /api/health   -> service + pipeline health check
  POST /api/analyze  -> run the full RAG scam/fraud analysis pipeline

All errors are caught and returned as clean JSON via ErrorResponse so the
frontend can always render a friendly message instead of crashing.
"""

import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.rag import RAGPipeline, RAGPipelineError
from app.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse, HealthResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("digital_guardian.main")

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Digital Guardian — RAG-powered scam & fraud alert assistant API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# The pipeline is constructed once at startup. If the knowledge base itself
# is missing/corrupt, we still want the app to boot (so /api/health can
# report the problem) rather than crash the whole process.
_pipeline: RAGPipeline | None = None
_pipeline_init_error: str | None = None

try:
    _pipeline = RAGPipeline(settings)
except RAGPipelineError as exc:
    _pipeline_init_error = str(exc)
    logger.error("RAG pipeline failed to initialize: %s", exc)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception while processing %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="internal_server_error",
            detail="Something went wrong on our side. Please try again in a moment.",
        ).model_dump(),
    )


@app.get("/api/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok" if _pipeline is not None else "degraded",
        app_name=settings.app_name,
        version=settings.app_version,
        llm_enabled=settings.llm_enabled,
        llm_provider=settings.llm_provider,
        knowledge_base_entries=_pipeline.knowledge_base_entries if _pipeline else 0,
    )


@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
    responses={400: {"model": ErrorResponse}, 503: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
def analyze_message(payload: AnalyzeRequest) -> AnalyzeResponse:
    if len(payload.message) > settings.max_message_length:
        raise HTTPException(
            status_code=400,
            detail=f"Message exceeds the maximum allowed length of {settings.max_message_length} characters.",
        )

    if _pipeline is None:
        raise HTTPException(
            status_code=503,
            detail=f"Analysis engine is currently unavailable: {_pipeline_init_error or 'unknown error'}",
        )

    try:
        return _pipeline.analyze(payload.message)
    except Exception as exc:  # noqa: BLE001 - convert any pipeline failure into a clean HTTP error
        logger.exception("Pipeline analysis failed")
        raise HTTPException(
            status_code=500,
            detail="The analysis engine encountered an error while processing this message. Please try again.",
        ) from exc


@app.get("/")
def root() -> dict:
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "health": "/api/health",
    }
