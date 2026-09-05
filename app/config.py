"""
Digital Guardian - Application Configuration

Centralizes all environment-driven configuration using pydantic-settings.
No secrets are ever hardcoded here; everything is read from environment
variables (via a local .env file in development, or real environment
variables in production).
"""

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- App ---
    app_env: str = "development"
    app_name: str = "Digital Guardian API"
    app_version: str = "1.0.0"

    # --- CORS ---
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- LLM Provider abstraction ---
    llm_provider: str = "none"  # "anthropic" | "openai" | "none"
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-6"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    # --- RAG / validation ---
    max_message_length: int = 4000
    retrieval_top_k: int = 4

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def llm_enabled(self) -> bool:
        """True only if a provider is selected AND its API key is actually present."""
        if self.llm_provider == "anthropic":
            return bool(self.anthropic_api_key)
        if self.llm_provider == "openai":
            return bool(self.openai_api_key)
        return False


@lru_cache
def get_settings() -> Settings:
    return Settings()
