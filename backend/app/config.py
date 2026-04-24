"""
config.py
---------
Centralised configuration for Splunk Sentinel.

All environment variables are validated at startup via Pydantic BaseSettings.
A single `settings` instance is exported and shared across the application.
"""

import logging
import os
from typing import Optional

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Splunk ────────────────────────────────────────────────────────────────
    SPLUNK_HOST: str = Field(default="localhost", description="Splunk server hostname")
    SPLUNK_PORT: int = Field(default=8089, description="Splunk management port (REST API)")
    SPLUNK_USERNAME: str = Field(
        ..., 
        validation_alias="SPLUNK_USERNAME", 
        alias="SPLUNK_USER",
        description="Splunk administrator username"
    )
    SPLUNK_PASSWORD: str = Field(..., description="Splunk administrator password")

    # ── OpenAI ────────────────────────────────────────────────────────────────
    OPENAI_API_KEY: str = Field(..., description="OpenAI API key")

    # ── LangSmith / LangChain tracing ─────────────────────────────────────────
    LANGCHAIN_TRACING_V2: str = Field(
        default="true", description="Enable LangSmith tracing"
    )
    LANGCHAIN_PROJECT: str = Field(
        default="splunk-sentinel", description="LangSmith project name"
    )
    LANGCHAIN_API_KEY: Optional[str] = Field(
        default=None, description="LangSmith API key (optional)"
    )

    @model_validator(mode="after")
    def _validate_required_secrets(self) -> "Settings":
        """
        Enforce that critical secrets are present and non-empty.

        Pydantic's `...` (required) already prevents missing keys, but this
        validator adds a human-readable error message for blank strings which
        can silently slip through when a .env entry exists but has no value.
        """
        missing: list[str] = []

        if not self.SPLUNK_USERNAME.strip():
            missing.append("SPLUNK_USERNAME")
        if not self.SPLUNK_PASSWORD.strip():
            missing.append("SPLUNK_PASSWORD")
        if not self.OPENAI_API_KEY.strip():
            missing.append("OPENAI_API_KEY")

        if missing:
            raise ValueError(
                f"The following required environment variables are empty or missing: "
                f"{', '.join(missing)}. "
                f"Set them in your .env file or shell environment before starting the server."
            )

        return self


# ---------------------------------------------------------------------------
# Singleton instance — import this everywhere in the application
# ---------------------------------------------------------------------------
settings = Settings()

# Export tracing and API keys to os.environ so LangChain/LangSmith SDKs pick them up
os.environ["LANGCHAIN_TRACING_V2"] = str(settings.LANGCHAIN_TRACING_V2).lower()
os.environ["LANGCHAIN_PROJECT"] = settings.LANGCHAIN_PROJECT
if settings.LANGCHAIN_API_KEY:
    os.environ["LANGCHAIN_API_KEY"] = settings.LANGCHAIN_API_KEY
os.environ["OPENAI_API_KEY"] = settings.OPENAI_API_KEY

logger.info(
    "Configuration loaded successfully. "
    "Splunk target: %s:%d | LangChain tracing: %s | Project: %s",
    settings.SPLUNK_HOST,
    settings.SPLUNK_PORT,
    settings.LANGCHAIN_TRACING_V2,
    settings.LANGCHAIN_PROJECT,
)
