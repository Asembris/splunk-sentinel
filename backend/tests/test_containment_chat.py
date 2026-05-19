import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock

from app.api.routes import router
from app.services.containment_chat import PersistentConstraintStore, get_initial_chat_message
from app.models.containment import ContainmentStatus, RiskLevel

client = TestClient(router)

def test_persistent_constraint_store_validation():
    # Test valid targets
    assert PersistentConstraintStore.validate_target("BLOCK_IP", "192.168.12.34") is None
    assert PersistentConstraintStore.validate_target("ISOLATE_HOST", "workstation-123") is None
    assert PersistentConstraintStore.validate_target("DISABLE_ACCOUNT", "jdoe") is None

    # Test protected IP blocking
    ip_violation = PersistentConstraintStore.validate_target("BLOCK_IP", "192.168.1.1")
    assert "falls within the system protected boundary" in ip_violation
    
    localhost_violation = PersistentConstraintStore.validate_target("BLOCK_IP", "127.0.0.1")
    assert "falls within the system protected boundary" in localhost_violation

    # Test protected hostname isolation
    host_violation = PersistentConstraintStore.validate_target("ISOLATE_HOST", "active-directory-controller")
    assert "critical infrastructure asset" in host_violation

    # Test protected user modifications
    user_violation = PersistentConstraintStore.validate_target("DISABLE_ACCOUNT", "administrator")
    assert "protected administrative identity" in user_violation


def test_initial_chat_message():
    msg = get_initial_chat_message()
    assert msg["sender"] == "assistant"
    assert "Splunk Sentinel" in msg["text"]
    assert "init_msg" == msg["id"]


@pytest.mark.asyncio
@patch("app.services.containment_chat.get_chat_history")
@patch("app.services.containment_chat.get_containment_plan_sync")
@patch("app.services.containment_chat.save_chat_history")
@patch("app.services.containment_chat.get_supabase_client")
async def test_handle_containment_chat_stream_add_action(
    mock_get_supabase_client,
    mock_save_history,
    mock_get_plan,
    mock_get_history
):
    from app.services.containment_chat import handle_containment_chat_stream, ContainmentChatResponse
    import app.services.containment_chat
    
    investigation_id = "test_inv_123"
    message = "Please block IP 192.168.99.99"
    
    mock_get_history.return_ok = True
    mock_get_history.return_value = []
    
    mock_get_plan.return_value = {
        "investigation_id": investigation_id,
        "phases": [{"actions": [], "status": "PENDING"}]
    }
    
    # Configure mock Supabase client
    mock_client = MagicMock()
    mock_get_supabase_client.return_value = mock_client
    mock_execute = MagicMock()
    mock_execute.data = {"report_json": {}}
    mock_client.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value = mock_execute
    
    # Mock LLM structured output to return an action suggestion by directly overriding module var
    mock_llm = AsyncMock()
    mock_llm.ainvoke.return_value = ContainmentChatResponse(
        reply="Sure, I will add a Block IP action for 192.168.99.99.",
        suggested_action_type="BLOCK_IP",
        suggested_action_target="192.168.99.99",
        suggested_action_reason="Suspicious outgoing connections detected.",
        action_to_delete_id=None
    )
    app.services.containment_chat._LLM_STRUCTURED = mock_llm
    
    events = []
    async for event in handle_containment_chat_stream(investigation_id, message):
        events.append(event)
        
    # Check that events are generated correctly
    assert any("response_start" in ev for ev in events)
    assert any("response_token" in ev for ev in events)
    assert any("response_complete" in ev for ev in events)
    assert any("plan_updated" in ev for ev in events)
    assert any("done" in ev for ev in events)
    
    # Check that save_chat_history was called with the user and assistant messages
    mock_save_history.assert_called_once()
    saved_history = mock_save_history.call_args[0][1]
    assert len(saved_history) == 3 # init_msg + user_msg + assistant_msg
    assert saved_history[1]["sender"] == "user"
    assert saved_history[2]["sender"] == "assistant"
    assert saved_history[2]["added_action"]["target"] == "192.168.99.99"
