import os
import uuid
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, AsyncGenerator, List
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

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

RFC1918_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",  # link-local
    "127.",      # loopback
)

def _is_internal_ip(ip: str) -> bool:
    """Return True if IP is RFC1918 or otherwise non-routable."""
    return any(ip.startswith(prefix) for prefix in RFC1918_PREFIXES)


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
        
        action_type_upper = action_type.upper().strip()
        if action_type_upper == "BLOCK_IP":
            if target in cls.PROTECTED_IPS or t_lower in ["localhost", "127.0.0.1"]:
                return f"IP address '{target}' falls within the system protected boundary (gateway, SIEM, DNS) and cannot be blocked."
        elif action_type_upper == "ISOLATE_HOST":
            if t_lower in cls.PROTECTED_HOSTNAMES or any(ph in t_lower for ph in cls.PROTECTED_HOSTNAMES):
                return f"Host '{target}' is a critical infrastructure asset and cannot be isolated."
        elif action_type_upper in ["DISABLE_ACCOUNT", "REVOKE_CREDENTIALS"]:
            if t_lower in cls.PROTECTED_USERS or any(pu in t_lower for pu in cls.PROTECTED_USERS):
                return f"User account '{target}' is a protected administrative identity and cannot be modified."
        return None

# Define ReAct Tools using Pydantic Models
class AddContainmentAction(BaseModel):
    """Adds a new containment action to the plan."""
    action_type: str = Field(description="Type of action: BLOCK_IP, ISOLATE_HOST, KILL_PROCESS, REVOKE_CREDENTIALS, DISABLE_ACCOUNT, ROTATE_CREDENTIALS, AUDIT_CLOUDTRAIL")
    action_target: str = Field(description="The target entity of the action (IP, hostname, username, process, etc.).")
    action_reason: Optional[str] = Field(None, description="The security rationale/justification for adding this action.")
    phase: int = Field(description="The phase number (1, 2, or 3) where the action should be added. Phase 1 = Immediate, Phase 2 = Short Term, Phase 3 = Remediation.")

class DeleteContainmentAction(BaseModel):
    """Deletes an existing containment action from the plan."""
    action_id: Optional[str] = Field(None, description="The unique ID of the existing action to delete.")
    action_type: Optional[str] = Field(None, description="If action_id is unknown, specify the action type (e.g. BLOCK_IP) to match for deletion.")
    action_target: Optional[str] = Field(None, description="If action_id is unknown, specify the action target (e.g. 184.85.20.125) to match for deletion.")


# LLM setup
_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0)
_LLM_WITH_TOOLS = _LLM.bind_tools([AddContainmentAction, DeleteContainmentAction])

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
    SSE stream handler for containment plan conversation using ReAct Tool-Calling Loop.
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

    # 3. Apply rolling window memory
    system_prompt = f"""You are Splunk Sentinel, an expert virtual Incident Response assistant.
Your task is to help the analyst refine the containment plan dynamically.

Current Containment Plan:
{json.dumps(plan_dict, indent=2)}

You can suggest adding or deleting containment actions by calling the provided tools.
You can call the tools MULTIPLE times in a single turn if the user asks for multiple actions (e.g. "block IP X and IP Y", or "remove all block IPs").

CRITICAL RULES:
- For block_ip: ONLY use IP addresses that appear in the CURRENT PLAN STATE provided above as existing action targets, OR IPs explicitly mentioned by the analyst in their message. NEVER invent, guess, or extrapolate IP addresses. NEVER use RFC1918 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x) as block_ip targets — these are internal IPs that cannot be blocked at perimeter.
- Core network gateways (192.168.1.1), primary DNS (8.8.8.8, 1.1.1.1), the Splunk SIEM server itself (10.0.0.10), domain controllers (domain-controller), and core administrator accounts (admin, system) MUST NOT be targeted.
- If deleting, try to provide the exact `action_id`. If unavailable, provide BOTH the `action_type` and `action_target` to safely match it.
- After all tool executions are complete, write a conversational response summarizing the successful actions and any errors that occurred (based on the tool execution results).
"""

    messages = [SystemMessage(content=system_prompt)]
    
    recent_history = history[-10:]
    for h in recent_history:
        if h.get("sender") == "user":
            messages.append(HumanMessage(content=h.get("text", "")))
        else:
            messages.append(AIMessage(content=h.get("text", "")))
            
    messages.append(HumanMessage(content=message))

    # 4. Tool-Calling Loop
    plan_updated = False
    added_actions_meta = []
    deleted_actions_meta = []
    reply = ""

    max_iterations = 5
    for iteration in range(max_iterations):
        try:
            res = await _LLM_WITH_TOOLS.ainvoke(messages)
            messages.append(res)
        except Exception as e:
            logger.error("[CHAT] LLM invocation failed: %s", str(e))
            reply = f"I encountered an error querying the model: {str(e)}"
            break

        if not res.tool_calls:
            # Done! It responded with text
            reply = res.content
            break

        # Execute tool calls
        for tool_call in res.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]
            tool_call_id = tool_call["id"]

            if tool_name == "AddContainmentAction":
                action_type = tool_args.get("action_type")
                action_target = tool_args.get("action_target")
                action_reason = tool_args.get("action_reason")
                phase_num = tool_args.get("phase", 1)

                if not action_type or not action_target:
                    messages.append(ToolMessage(content="Error: action_type and action_target are required.", tool_call_id=tool_call_id))
                    continue

                violation = PersistentConstraintStore.validate_target(action_type, action_target)
                if violation:
                    messages.append(ToolMessage(content=f"Error: {violation}", tool_call_id=tool_call_id))
                    continue

                target_phase_num = phase_num if phase_num in (1, 2, 3) else 1
                target_phase_idx = target_phase_num - 1

                # Duplicate detection
                duplicate_found = False
                for p in plan_dict.get("phases", []):
                    for a in p.get("actions", []):
                        if (a.get("type", "").upper() == action_type.upper() and
                                a.get("target", "").strip().lower() == action_target.strip().lower()):
                            duplicate_found = True
                            break
                    if duplicate_found:
                        break

                if duplicate_found:
                    messages.append(ToolMessage(content=f"Error: Duplicate action. {action_type} for '{action_target}' already exists.", tool_call_id=tool_call_id))
                    continue

                # Add Action
                new_id = f"chat_{uuid.uuid4().hex[:8]}"
                reason_text = action_reason or f"Refined via chat: {message}"
                spl, rev = generate_action_spl(
                    action_type=action_type,
                    target=action_target,
                    reason=reason_text,
                    investigation_id=investigation_id,
                    action_id=new_id,
                    confidence=1.0,
                    phase=target_phase_num
                )
                
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
                    "phase": target_phase_num,
                    "risk_level": risk_level,
                    "executed_by": "Sentinel Chat Assistant"
                }
                
                if "phases" in plan_dict and len(plan_dict["phases"]) > target_phase_idx:
                    plan_dict["phases"][target_phase_idx]["actions"].append(new_action_dict)
                    plan_updated = True
                    added_actions_meta.append({
                        "id": new_id,
                        "type": action_type,
                        "target": action_target,
                        "phase": target_phase_num
                    })
                    messages.append(ToolMessage(content=f"Success: Added {action_type} for '{action_target}'.", tool_call_id=tool_call_id))
                else:
                    messages.append(ToolMessage(content=f"Error: Invalid phase {target_phase_num}.", tool_call_id=tool_call_id))

            elif tool_name == "DeleteContainmentAction":
                target_id = (tool_args.get("action_id") or "").strip()
                del_type = (tool_args.get("action_type") or "").strip().upper()
                del_target = (tool_args.get("action_target") or "").strip().lower()

                deleted_count = 0
                for p in plan_dict.get("phases", []):
                    actions = p.get("actions", [])
                    new_actions = []
                    for a in actions:
                        match = False
                        if target_id and (a.get("id") == target_id or a.get("action_id") == target_id):
                            match = True
                        elif del_type and del_target and a.get("type", "").upper() == del_type and a.get("target", "").strip().lower() == del_target:
                            match = True
                            
                        if match:
                            deleted_count += 1
                            deleted_actions_meta.append({
                                "id": a.get("id", "unknown"),
                                "type": a.get("type"),
                                "target": a.get("target")
                            })
                        else:
                            new_actions.append(a)
                    p["actions"] = new_actions

                if deleted_count > 0:
                    plan_updated = True
                    messages.append(ToolMessage(content=f"Success: Deleted {deleted_count} matching actions.", tool_call_id=tool_call_id))
                else:
                    messages.append(ToolMessage(content="Error: No matching action found to delete.", tool_call_id=tool_call_id))
            else:
                messages.append(ToolMessage(content=f"Error: Unknown tool {tool_name}", tool_call_id=tool_call_id))

    else:
        # Reached max iterations
        reply = "I attempted to process your request but reached the maximum number of operations allowed in one step."

    # 5. Stream response reply token-by-token
    yield "event: response_start\ndata: {}\n\n"
    words = reply.split(" ")
    for i, w in enumerate(words):
        space = " " if i < len(words) - 1 else ""
        yield f"event: response_token\ndata: {json.dumps({'token': w + space})}\n\n"
        await asyncio.sleep(0.01)

    # 6. Emit response_complete with arrays of action metadata
    complete_payload = {'reply': reply}
    if added_actions_meta:
        complete_payload['added_actions'] = added_actions_meta
    if deleted_actions_meta:
        complete_payload['deleted_actions'] = deleted_actions_meta
    yield f"event: response_complete\ndata: {json.dumps(complete_payload)}\n\n"

    # 7. Save updated plan and stream plan_updated
    if plan_updated:
        plan_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
        yield f"event: plan_updated\ndata: {json.dumps({'plan': plan_dict})}\n\n"
        
        try:
            client = get_supabase_client()
            response = client.table("investigations").select("report_json").eq("investigation_id", investigation_id).single().execute()
            existing = response.data or {}
            report_json = existing.get("report_json") or {}
            report_json["containment_plan"] = plan_dict
            
            client.table("investigations").update(
                {"report_json": report_json}
            ).eq("investigation_id", investigation_id).execute()
        except Exception as e:
            logger.error("[CHAT] Failed to persist modified plan: %s", str(e))

    # 8. Append messages to chat history and persist
    new_user_msg = {
        "id": f"msg_{uuid.uuid4().hex[:8]}",
        "sender": "user",
        "text": message,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Store multiple actions for legacy UI components if they exist, to prevent breaking
    legacy_added = added_actions_meta[0] if added_actions_meta else None
    legacy_deleted = deleted_actions_meta[0] if deleted_actions_meta else None
    
    new_assistant_msg = {
        "id": f"msg_{uuid.uuid4().hex[:8]}",
        "sender": "assistant",
        "text": reply,
        "added_actions": added_actions_meta,
        "deleted_actions": deleted_actions_meta,
        "added_action": legacy_added,      # Backward compatibility
        "deleted_action": legacy_deleted,  # Backward compatibility
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    history.append(new_user_msg)
    history.append(new_assistant_msg)
    save_chat_history(investigation_id, history)

    yield "event: done\ndata: {}\n\n"
