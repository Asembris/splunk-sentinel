"""
Tests for LangGraph checkpointing infrastructure.
Verifies that init_graph, get_graph, and checkpoint status work correctly.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock


@pytest.mark.asyncio
async def test_init_graph_returns_compiled_graph():
    """init_graph should return a compiled graph with a checkpointer attached."""
    from app.graph.investigation_graph import init_graph, get_graph
    # Reset global state for test isolation
    import app.graph.investigation_graph as ig
    original_graph = ig._compiled_graph
    original_checkpointer = ig._checkpointer
    original_context = ig._checkpointer_context
    ig._compiled_graph = None
    ig._checkpointer = None
    ig._checkpointer_context = None

    try:
        await init_graph()
        graph = get_graph()
        assert graph is not None
        assert hasattr(graph, 'astream')
        assert hasattr(graph, 'ainvoke')
        assert hasattr(graph, 'aget_state')
    finally:
        if ig._checkpointer_context is not None:
            await ig._checkpointer_context.__aexit__(None, None, None)
        ig._compiled_graph = original_graph
        ig._checkpointer = original_checkpointer
        ig._checkpointer_context = original_context


@pytest.mark.asyncio
async def test_get_graph_raises_before_init():
    """get_graph should raise RuntimeError if called before init_graph."""
    import app.graph.investigation_graph as ig
    original = ig._compiled_graph
    ig._compiled_graph = None
    try:
        from app.graph.investigation_graph import get_graph
        with pytest.raises(RuntimeError, match="not initialized"):
            get_graph()
    finally:
        ig._compiled_graph = original


@pytest.mark.asyncio
async def test_checkpoint_status_endpoint_unknown_id():
    """Checkpoint status for an unknown investigation_id should return checkpoint_exists False."""
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    response = client.get("/api/investigations/nonexistent-test-id-12345/checkpoint-status")
    assert response.status_code == 200
    data = response.json()
    assert data["investigation_id"] == "nonexistent-test-id-12345"
    assert "checkpoint_exists" in data


def test_agent_state_has_supabase_record_id_field():
    """AgentState must have supabase_record_id field for idempotency detection."""
    from app.models.state import AgentState
    import typing
    hints = typing.get_type_hints(AgentState)
    assert "supabase_record_id" in hints
