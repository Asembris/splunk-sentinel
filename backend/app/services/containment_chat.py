import os
import uuid
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, AsyncGenerator
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage

from app.models.containment import (
    ContainmentAction,
    ContainmentActionType,
    ContainmentStatus,
    RiskLevel
)
from app.services.supabase_client import (
    get_containment_plan_sync,
    get_chat_history,
    save_chat_history,
    is_plan_locked,
    release_plan_lock_sync
)
from app.services.containment_templates import generate_action_spl, get_template_metadata
from app.services.supabase_client import get_supabase_client

logger = logging.getLogger(__name__)

# Structured LLM Output schema
class ContainmentChatResponse(BaseModel):
    reply: str = Field(description="The conversational response to the security analyst.")
    suggested_action_type: Optional[str] = Field(None, description="Type of action to suggest/add: BLOCK_IP, ISOLATE_HOST, KILL_PROCESS, REVOKE_CREDENTIALS, DISABLE_ACCOUNT, ROTATE_CREDENTIALS, AUDIT_CLOUDTRAIL.")
    suggested_action_target: Optional[str] = Field(None, description="The target entity of the suggested action (IP, hostname, username, process, etc.).")
    suggested_action_reason: Optional[str] = Field(None, description="The security rationale/justification for adding this action.")
    action_to_delete_id: Optional[str] = Field(None, description="The unique ID of the existing action to delete from the plan.")


class PersistentConstraintStore:
    """
    Safety constraint store to enforce system security boundaries.
    Prevents blocking primary DNS, core gateways, Splunk servers, or administrative identity assets.
    """
    PROTECTED_IPS = {"192.168.1.1", "10.0.0.10", "8.8.8.8", "1.1.1.1"}
    PROTECTED_HOSTNAMES = {"splunk-server", "active-directory-controller", "domain-controller"}
    PROTECTED_USERS = {"admin", "administrator", "system"}

    @classmethod
    def validate_target(cls, action_type: str, target: str) -> Optional[str]:
        if not target:
            return "Target entity cannot be empty."
        t_lower = target.lower().strip()
        
        if action_type == "BLOCK_IP":
            if target in cls.PROTECTED_IPS or t_lower in ["localhost", "127.0.0.1"]:
                return f"IP address '{target}' falls within the system protected boundary (gateway, SIEM, DNS) and cannot be blocked."
        elif action_type == "ISOLATE_HOST":
            if t_lower in cls.PROTECTED_HOSTNAMES or any(ph in t_lower for ph in cls.PROTECTED_HOSTNAMES):
                return f"Host '{target}' is a critical infrastructure asset and cannot be isolated."
        elif action_type in ["DISABLE_ACCOUNT", "REVOKE_CREDENTIALS"]:
            if t_lower in cls.PROTECTED_USERS or any(pu in t_lower for pu in cls.PROTECTED_USERS):
                return f"User account '{target}' is a protected administrative identity and cannot be modified."
        return None


# LLM setup
_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0)
_LLM_STRUCTURED = _LLM.with_structured_output(ContainmentChatResponse)


def get_initial_chat_message() -> dict:
    """
    Generates the deterministic initial assistant message.
    Zero LLM calls.
    """
    return {
        "id": "init_msg",
        "sender": "assistant",
        "text": "Hello! I am Splunk Sentinel, your virtual Incident Response containment assistant. "
                "I can help you refine, add, or delete containment actions interactively. "
                "Ask me to 'block IP 192.168.4.5', 'isolate host workstation-xyz', 'remove isolated host action', etc.",
        "created_at": "2026-05-19T12:00:00Z"
    }


async def handle_containment_chat_stream(investigation_id: str, message: str) -> AsyncGenerator[str, None]:
    """
    SSE stream handler for containment plan conversation.
    Streams progress events and final status.
    """
    # 1. Check if the plan is currently locked for execution
    if is_plan_locked(investigation_id):
        locked_msg = "I cannot modify the containment plan right now because a phase is currently locked and executing. Please wait up to 300 seconds for the operation to complete."
        yield "event: response_start\ndata: {}\n\n"
        for word in locked_msg.split():
            yield f"event: response_token\ndata: {json.dumps({'token': word + ' '})}\n\n"
            await asyncio.sleep(0.02)
        yield f"event: response_complete\ndata: {json.dumps({'reply': locked_msg})}\n\n"
        yield "event: done\ndata: {}\n\n"
        return

    # 2. Retrieve history and plan
    history = get_chat_history(investigation_id) or []
    if not history:
        history = [get_initial_chat_message()]

    plan_dict = get_containment_plan_sync(investigation_id)
    if not plan_dict:
        yield "event: response_start\ndata: {}\n\n"
        err_msg = "Error: Containment plan not found for this investigation."
        yield f"event: response_token\ndata: {json.dumps({'token': err_msg})}\n\n"
        yield f"event: response_complete\ndata: {json.dumps({'reply': err_msg})}\n\n"
        yield "event: done\ndata: {}\n\n"
        return

    # 3. Apply rolling window memory (keep system prompt context + last 10 messages)
    system_prompt = f"""You are Splunk Sentinel, an expert virtual Incident Response assistant.
Your task is to help the analyst refine the containment plan dynamically.

Current Containment Plan:
{json.dumps(plan_dict, indent=2)}

You can suggest:
1. Adding new containment actions (type must be one of: BLOCK_IP, ISOLATE_HOST, KILL_PROCESS, REVOKE_CREDENTIALS, DISABLE_ACCOUNT, ROTATE_CREDENTIALS, AUDIT_CLOUDTRAIL).
2. Deleting an existing action by identifying its target/type and returning its 'id' in 'action_to_delete_id'.

Constraints & Safety Boundaries:
- Core network gateways (192.168.1.1), primary DNS (8.8.8.8, 1.1.1.1), the Splunk SIEM server itself (10.0.0.10), domain controllers (domain-controller), and core administrator accounts (admin, system) MUST NOT be targeted.
- Always provide highly professional, concise, and defensive security rationale.

Response Format:
Always respond with the specified structure containing:
- 'reply': A conversational explanation of what you are doing (e.g. 'I will add a Block IP action for...')
- 'suggested_action_type': string or null
- 'suggested_action_target': string or null
- 'suggested_action_reason': string or null
- 'action_to_delete_id': string or null
"""

    messages = [SystemMessage(content=system_prompt)]
    
    # Extract only last 10 messages from chat history for context window
    recent_history = history[-10:]
    for h in recent_history:
        if h.get("sender") == "user":
            messages.append(HumanMessage(content=h.get("text", "")))
        else:
            messages.append(AIMessage(content=h.get("text", "")))
            
    # Append the new user message
    messages.append(HumanMessage(content=message))

    # 4. Invoke Structured LLM
    try:
        res: ContainmentChatResponse = await _LLM_STRUCTURED.ainvoke(messages)
    except Exception as e:
        logger.error("[CHAT] LLM invocation failed: %s", str(e))
        yield "event: response_start\ndata: {}\n\n"
        err_msg = f"I encountered an error querying the model: {str(e)}"
        yield f"event: response_token\ndata: {json.dumps({'token': err_msg})}\n\n"
        yield f"event: response_complete\ndata: {json.dumps({'reply': err_msg})}\n\n"
        yield "event: done\ndata: {}\n\n"
        return

    reply = res.reply
    action_type = res.suggested_action_type
    action_target = res.suggested_action_target
    action_reason = res.suggested_action_reason
    action_to_delete_id = res.action_to_delete_id

    # 5. Stream response reply token-by-token
    yield "event: response_start\ndata: {}\n\n"
    # Stream simulated tokens of the reply
    words = reply.split(" ")
    for i, w in enumerate(words):
        space = " " if i < len(words) - 1 else ""
        yield f"event: response_token\ndata: {json.dumps({'token': w + space})}\n\n"
        await asyncio.sleep(0.01) # fast premium simulated stream
    yield f"event: response_complete\ndata: {json.dumps({'reply': reply})}\n\n"

    # 6. Safety check on suggested actions
    plan_updated = False
    added_action_meta = None
    deleted_action_meta = None

    if action_type and action_target:
        # Validate against safety boundaries
        violation = PersistentConstraintStore.validate_target(action_type, action_target)
        if violation:
            # Yield safety violation response instead of adding it
            yield f"event: response_token\ndata: {json.dumps({'token': f'\\n\\n[SAFETY ALERT] {violation}'})}\n\n"
            reply += f"\n\n[SAFETY ALERT] {violation}"
        else:
            # Generate new action
            new_id = f"chat_{uuid.uuid4().hex[:8]}"
            reason_text = action_reason or f"Refined via chat: {message}"
            spl, rev = generate_action_spl(
                action_type=action_type,
                target=action_target,
                reason=reason_text,
                investigation_id=investigation_id,
                action_id=new_id,
                confidence=1.0,
                phase=1
            )
            
            # Map metadata for risk level
            is_irr = (rev is None) or (action_type in ["ROTATE_CREDENTIALS", "AUDIT_CLOUDTRAIL", "KILL_PROCESS", "REVOKE_CREDENTIALS"])
            risk_level = RiskLevel.HIGH if is_irr else RiskLevel.MEDIUM
            
            new_action_dict = {
                "id": new_id,
                "action_id": new_id,
                "type": action_type,
                "title": f"Refined: {action_type.replace('_', ' ').title()}",
                "description": reason_text,
                "target": action_target,
                "containment_spl": spl,
                "reversal_spl": rev,
                "status": ContainmentStatus.PENDING,
                "is_irreversible": is_irr,
                "reversible": not is_irr,
                "phase": 1,
                "risk_level": risk_level,
                "executed_by": "Sentinel Chat Assistant"
            }
            
            # Insert to phase 1
            if "phases" in plan_dict and len(plan_dict["phases"]) > 0:
                plan_dict["phases"][0]["actions"].append(new_action_dict)
                plan_updated = True
                added_action_meta = {
                    "id": new_id,
                    "type": action_type,
                    "target": action_target
                }
                logger.info("[CHAT] Added action %s to Phase 1", new_id)

    # 7. Check for Deletion request
    if action_to_delete_id:
        target_id = action_to_delete_id.strip()
        deleted = False
        for phase in plan_dict.get("phases", []):
            actions = phase.get("actions", [])
            for action in list(actions):
                if action.get("id") == target_id or action.get("action_id") == target_id:
                    actions.remove(action)
                    deleted = True
                    deleted_action_meta = {
                        "id": target_id,
                        "type": action.get("type"),
                        "target": action.get("target")
                    }
                    break
            if deleted:
                break
        if deleted:
            plan_updated = True
            logger.info("[CHAT] Deleted action %s successfully", target_id)

    # 8. Save updated plan and stream plan_updated
    if plan_updated:
        # Sync timestamp
        plan_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        # Patch containment plan in investigations
        try:
            client = get_supabase_client()
            response = client.table("investigations").select("report_json").eq("investigation_id", investigation_id).single().execute()
            existing = response.data or {}
            report_json = existing.get("report_json") or {}
            report_json["containment_plan"] = plan_dict
            
            client.table("investigations").update(
                {"report_json": report_json}
            ).eq("investigation_id", investigation_id).execute()
            
            yield f"event: plan_updated\ndata: {json.dumps(plan_dict)}\n\n"
        except Exception as e:
            logger.error("[CHAT] Failed to persist modified plan: %s", str(e))

    # 9. Append messages to chat history and persist
    new_user_msg = {
        "id": f"msg_{uuid.uuid4().hex[:8]}",
        "sender": "user",
        "text": message,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    new_assistant_msg = {
        "id": f"msg_{uuid.uuid4().hex[:8]}",
        "sender": "assistant",
        "text": reply,
        "added_action": added_action_meta,
        "deleted_action": deleted_action_meta,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    history.append(new_user_msg)
    history.append(new_assistant_msg)
    
    save_chat_history(investigation_id, history)

    yield "event: done\ndata: {}\n\n"
