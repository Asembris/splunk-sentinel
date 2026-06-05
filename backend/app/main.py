"""
main.py
-------
FastAPI application entry point for Splunk Sentinel.

Responsibilities:
  - Create and configure the FastAPI app instance.
  - Register CORS middleware (allow React dev server at localhost:5173).
  - Mount the API router from routes.py.
  - Startup event: verify Splunk connectivity, ensure logs/ directory exists.
  - Global exception handler: structured JSON error responses.
"""

from __future__ import annotations

import truststore
truststore.inject_into_ssl()

import asyncio
import logging
import logging.config
import traceback
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.graph.investigation_graph import init_graph
from app.utils.prompt_loader import validate_prompts_on_startup

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

# Ensure logs directory exists (relative to backend/ CWD, same as spl_audit.log)
logs_dir = Path("logs")
logs_dir.mkdir(parents=True, exist_ok=True)

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "detailed": {
                "format": "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%S",
            }
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "detailed",
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": "logs/splunk_sentinel.log",
                "maxBytes": 10_485_760,   # 10 MB per file
                "backupCount": 5,
                "formatter": "detailed",
                "encoding": "utf-8",
            },
        },
        "root": {
            "level": "INFO",
            "handlers": ["console", "file"],
        },
        "loggers": {
            "uvicorn.error": {"propagate": True},
            "uvicorn.access": {"propagate": True},
            "httpx": {"level": "WARNING", "propagate": True},
            "splunklib": {"level": "WARNING", "propagate": True},
        },
    }
)

logger = logging.getLogger(__name__)

LANGFUSE_PROMPTS = [
    "triage-agent",
    "reconstruction-agent",
    "synthesis-narrative",
    "synthesis-containment",
    "synthesis-counterfactual",
    "containment-refinement",
]

# ---------------------------------------------------------------------------
# Startup / shutdown lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.
    """
    logger.info("Splunk Sentinel starting up …")

    # Import config here (triggers pydantic validation & raises on bad env)
    try:
        from app.config import settings
        logger.info("Config validated. Splunk target: %s:%d", settings.SPLUNK_HOST, settings.SPLUNK_PORT)
    except Exception as exc:
        logger.critical("Configuration error: %s", exc)
        raise

    await init_graph()

    # Test Splunk connection
    try:
        from app.tools.splunk_tools import SplunkClient
        # Use a simple connection test that doesn't block the loop
        def test_conn():
            return SplunkClient().service.info.get("version", "unknown")
            
        loop = asyncio.get_event_loop()
        version = await loop.run_in_executor(None, test_conn)
        logger.info("✅ Splunk connection verified. Version: %s", version)
    except Exception as exc:
        logger.warning("⚠️ Splunk connection check FAILED: %s", exc)

    validate_prompts_on_startup(LANGFUSE_PROMPTS)

    yield
    logger.info("Splunk Sentinel shutting down.")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Returns:
        Configured FastAPI instance ready for uvicorn.
    """
    app = FastAPI(
        title="Splunk Sentinel",
        description=(
            "Production-grade autonomous security investigation system. "
            "Powered by LangGraph + GPT-4o-mini + Splunk Enterprise."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS ─────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",   # React / Vite dev server
            "http://127.0.0.1:5173",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Router ────────────────────────────────────────────────────────────────
    app.include_router(router)
    from app.api.webhook import router as webhook_router
    app.include_router(webhook_router)

    # ── Global exception handler ─────────────────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Catch-all exception handler.

        Returns a structured JSON error response so the React frontend always
        gets a parseable body, even for 500-level errors.

        Args:
            request: The incoming FastAPI Request.
            exc:     The unhandled exception.

        Returns:
            JSONResponse with ``error``, ``investigation_id``, and
            ``detail`` fields.
        """
        investigation_id: str | None = None
        try:
            # Best-effort: try to extract investigation_id from the request body
            body = await request.json()
            investigation_id = body.get("investigation_id")
        except Exception:
            pass

        logger.error(
            "Unhandled exception | path=%s | id=%s | error=%s\n%s",
            request.url.path,
            investigation_id,
            exc,
            traceback.format_exc(),
        )

        return JSONResponse(
            status_code=500,
            content={
                "error": str(exc),
                "investigation_id": investigation_id,
                "detail": (
                    "An unexpected error occurred. "
                    "Check server logs for the full traceback."
                ),
            },
        )

    return app


# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------

app = create_app()

# ---------------------------------------------------------------------------
# Dev entrypoint (python -m app.main)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
    )
