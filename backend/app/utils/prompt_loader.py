"""
PromptOps layer for Splunk Sentinel.
Manages prompts via Langfuse with versioning, labels,
and graceful fallback to hardcoded strings.

Design principles:
- Langfuse is the source of truth for prompts
- 5-minute local cache prevents redundant API calls
- Hardcoded fallbacks guarantee pipeline never crashes
- Startup validation catches missing prompts early
- Never raises in production - always returns a prompt
"""

import logging
import os

import truststore

logger = logging.getLogger(__name__)
truststore.inject_into_ssl()

# In-memory cache: populated on first successful Langfuse fetch
# Key: "prompt_name:label"
# Value: compiled prompt string
_local_cache: dict[str, str] = {}

# Track which prompts have been validated at startup
_validated: set[str] = set()


def _render_fallback(fallback: str, **variables) -> str:
    """Best-effort variable interpolation for local fallback prompts."""
    rendered = fallback
    for key, value in variables.items():
        value_str = str(value)
        rendered = rendered.replace(f"{{{{{key}}}}}", value_str)
        rendered = rendered.replace(f"{{{key}}}", value_str)
    return rendered


def _get_client():
    """
    Get Langfuse client.
    Returns None if credentials missing or init fails.
    Never raises.
    """
    try:
        public_key = os.getenv("LANGFUSE_PUBLIC_KEY", "")
        secret_key = os.getenv("LANGFUSE_SECRET_KEY", "")
        host = os.getenv(
            "LANGFUSE_HOST", "https://cloud.langfuse.com"
        )

        if not public_key or not secret_key:
            logger.debug(
                "[PromptLoader] No Langfuse credentials - "
                "using fallbacks"
            )
            return None

        from langfuse import Langfuse
        return Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=host,
        )
    except Exception as e:
        logger.warning(
            "[PromptLoader] Client init failed: %s", str(e)
        )
        return None


def get_prompt(
    name: str,
    fallback: str,
    label: str = "production",
    **variables,
) -> str:
    """
    Fetch and compile a prompt from Langfuse.

    Args:
        name: Prompt name in Langfuse (e.g. "triage-agent")
        fallback: Hardcoded string used when Langfuse
                  is unavailable. Required - never optional.
        label: Langfuse label to fetch ("production" or
               "staging"). Default: "production".
        **variables: Key-value pairs for {{variable}}
                     interpolation in the prompt template.

    Returns:
        Compiled prompt string ready to send to LLM.
        Always returns a non-empty string.

    Guarantees:
        - Never raises
        - Always returns the fallback if Langfuse fails
        - Caches successful fetches for 5 minutes
        - Logs all fallback activations as warnings
    """
    cache_key = f"{name}:{label}"

    try:
        client = _get_client()
        if client is None:
            raise RuntimeError("No Langfuse client")

        # Langfuse SDK handles its own 5-min TTL cache
        prompt_obj = client.get_prompt(
            name,
            label=label,
            cache_ttl_seconds=300,
        )

        # Compile with variables if provided
        if variables:
            compiled = prompt_obj.compile(**variables)
        else:
            compiled = prompt_obj.compile()

        # Update local fallback cache on success
        _local_cache[cache_key] = compiled

        logger.debug(
            "[PromptLoader] ✓ %s (label=%s version=%s)",
            name,
            label,
            getattr(prompt_obj, "version", "?"),
        )

        return compiled

    except Exception as e:
        logger.warning(
            "[PromptLoader] Fetch failed for '%s': %s "
            "- activating fallback",
            name,
            str(e),
        )

        # Try local memory cache (from previous successful fetch)
        if cache_key in _local_cache:
            logger.info(
                "[PromptLoader] Using memory cache for '%s'",
                name,
            )
            return _local_cache[cache_key]

        # Last resort: hardcoded fallback
        logger.warning(
            "[PromptLoader] Using hardcoded fallback for '%s'",
            name,
        )
        return _render_fallback(fallback, **variables)


def validate_prompts_on_startup(
    required: list[str],
    label: str = "production",
) -> None:
    """
    Validate required prompts are accessible at startup.
    Logs warnings for issues but never blocks startup.
    Call once from FastAPI lifespan.

    Args:
        required: List of prompt names to validate
        label: Label to validate against (default: production)
    """
    logger.info(
        "[PromptLoader] Validating %d prompts (label=%s)",
        len(required),
        label,
    )

    passed = []
    warned = []

    for name in required:
        try:
            client = _get_client()
            if client is None:
                warned.append(
                    f"{name}: no Langfuse credentials"
                )
                continue

            prompt_obj = client.get_prompt(
                name, label=label, cache_ttl_seconds=300
            )
            compiled = prompt_obj.compile()

            if len(compiled) < 50:
                warned.append(f"{name}: suspiciously short")
            else:
                _validated.add(name)
                passed.append(name)
                logger.info(
                    "[PromptLoader] ✓ %s (version=%s, "
                    "length=%d chars)",
                    name,
                    getattr(prompt_obj, "version", "?"),
                    len(compiled),
                )

        except Exception as e:
            warned.append(f"{name}: {str(e)}")

    if warned:
        logger.warning(
            "[PromptLoader] Prompt validation warnings: %s "
            "- hardcoded fallbacks will be used",
            warned,
        )
    else:
        logger.info(
            "[PromptLoader] All %d prompts validated ✓",
            len(passed),
        )


def get_prompt_version_info(name: str) -> dict:
    """
    Get metadata about the current production prompt.
    Used by the health endpoint and audit logging.
    Returns empty dict if unavailable.
    """
    try:
        client = _get_client()
        if client is None:
            return {}
        prompt_obj = client.get_prompt(
            name, label="production", cache_ttl_seconds=300
        )
        return {
            "name": name,
            "version": getattr(prompt_obj, "version", None),
            "label": "production",
        }
    except Exception:
        return {}
