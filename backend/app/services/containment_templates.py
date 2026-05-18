"""
containment_templates.py
------------------------
Catalog of safe, predefined SPL templates for containment actions.
Ensures that all remediation actions follow a strictly controlled syntax
and target only the permitted sentinel_actions index.
"""

import re
from typing import Dict, Any, Optional
from app.models.containment import ContainmentActionType


TEMPLATES: Dict[ContainmentActionType, Dict[str, Any]] = {
    ContainmentActionType.BLOCK_IP: {
        "title": "Block Malicious IP",
        "description": "Blacklist a source IP across the enterprise security boundary.",
        "spl": '| makeresults | eval ip="{{target}}", action="block", type="network", severity="high", reason="Sentinel investigation findings" | collect index=sentinel_actions',
        "reversal": '| makeresults | eval ip="{{target}}", action="unblock", type="network", reason="Sentinel analyst rollback" | collect index=sentinel_actions',
        "is_irreversible": False,
    },
    ContainmentActionType.ISOLATE_HOST: {
        "title": "Isolate Endpoint",
        "description": "Sever network connectivity for the affected host except for management and Sentinel traffic.",
        "spl": '| makeresults | eval host="{{target}}", action="isolate", type="endpoint", severity="critical" | collect index=sentinel_actions',
        "reversal": '| makeresults | eval host="{{target}}", action="rejoin", type="endpoint", reason="Post-investigation restoration" | collect index=sentinel_actions',
        "is_irreversible": False,
    },
    ContainmentActionType.DISABLE_ACCOUNT: {
        "title": "Disable Compromised Account",
        "description": "Disable the compromised user account to prevent further access.",
        "spl": '| makeresults | eval user="{{target}}", action="disable", type="identity" | collect index=sentinel_actions',
        "reversal": '| makeresults | eval user="{{target}}", action="enable", type="identity", reason="Analyst reactivation" | collect index=sentinel_actions',
        "is_irreversible": False,
    },
    ContainmentActionType.ROTATE_CREDENTIALS: {
        "title": "Rotate API Credentials",
        "description": "Rotate API keys and credentials associated with the target resource.",
        "spl": '| makeresults | eval user="{{target}}", action="rotate", type="identity" | collect index=sentinel_actions',
        "reversal": None,
        "is_irreversible": True,
    },
    ContainmentActionType.AUDIT_CLOUDTRAIL: {
        "title": "Audit CloudTrail logs",
        "description": "Initiate comprehensive log auditing on the target cloud resource.",
        "spl": '| makeresults | eval resource="{{target}}", action="audit", type="cloudtrail" | collect index=sentinel_actions',
        "reversal": None,
        "is_irreversible": True,
    },
    ContainmentActionType.KILL_PROCESS: {
        "title": "Terminate Malicious Process",
        "description": "Remotely terminate a process by name or PID.",
        "spl": '| makeresults | eval process="{{target}}", action="kill" | collect index=sentinel_actions',
        "reversal": None,  # Process termination is irreversible
        "is_irreversible": True,
    },
    ContainmentActionType.REVOKE_CREDENTIALS: {
        "title": "Revoke User Session",
        "description": "Invalidate all active sessions and force password reset for the compromised account.",
        "spl": '| makeresults | eval user="{{target}}", action="revoke", type="identity" | collect index=sentinel_actions',
        "reversal": None,  # Credential revocation is effectively irreversible via SPL
        "is_irreversible": True,
    },
}

CONTAINMENT_TEMPLATES = TEMPLATES


def render_template(template_type: ContainmentActionType, target: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Render an SPL template with the provided target and context.
    """
    template_data = TEMPLATES.get(template_type)
    if not template_data:
        raise ValueError(f"Unknown containment template type: {template_type}")

    spl = template_data["spl"].replace("{{target}}", target)
    reversal = template_data["reversal"]
    if reversal:
        reversal = reversal.replace("{{target}}", target)

    if context:
        for key, value in context.items():
            spl = spl.replace(f"{{{{{key}}}}}", str(value))
            if reversal:
                reversal = reversal.replace(f"{{{{{key}}}}}", str(value))

    return {
        "spl": spl,
        "reversal": reversal,
        "title": template_data["title"],
        "description": template_data["description"],
        "is_irreversible": template_data.get("is_irreversible", reversal is None)
    }


# ---------------------------------------------------------------------------
# Test Compatibility functions
# ---------------------------------------------------------------------------

def _sanitize_spl_value(val: str) -> str:
    """
    Strip double quotes, pipes, backticks, backslashes, square brackets.
    Truncate target to 200 characters max.
    """
    if not val:
        return ""
    sanitized = re.sub(r'["|`\\\[\]]', "", val)
    return sanitized[:200]


def generate_action_spl(
    action_type: Any,
    target: str,
    reason: str,
    investigation_id: str,
    action_id: str,
    confidence: float = 1.0,
    phase: int = 1
) -> tuple[str, Optional[str]]:
    """
    Generate sanitized containment SPL and reversal SPL.
    Ensures that the generated SPL contains target, reason, investigation_id, and action_id.
    """
    if isinstance(action_type, str):
        try:
            enum_type = ContainmentActionType[action_type.upper()]
        except KeyError:
            raise ValueError(f"Unknown action type: {action_type}")
    else:
        enum_type = action_type

    template_data = TEMPLATES.get(enum_type)
    if not template_data:
        raise ValueError(f"Unknown action type: {action_type}")

    sanitized_target = _sanitize_spl_value(target)
    sanitized_reason = _sanitize_spl_value(reason)
    sanitized_investigation_id = _sanitize_spl_value(investigation_id)
    sanitized_action_id = _sanitize_spl_value(action_id)

    eval_fields = {}
    if enum_type == ContainmentActionType.BLOCK_IP:
        eval_fields["ip"] = sanitized_target
        eval_fields["action"] = "block"
        eval_fields["type"] = "network"
        eval_fields["severity"] = "high"
        eval_fields["host"] = "firewall"
    elif enum_type == ContainmentActionType.ISOLATE_HOST:
        eval_fields["host"] = sanitized_target
        eval_fields["action"] = "isolate"
        eval_fields["type"] = "endpoint"
        eval_fields["severity"] = "critical"
    elif enum_type == ContainmentActionType.DISABLE_ACCOUNT:
        eval_fields["user"] = sanitized_target
        eval_fields["action"] = "disable"
        eval_fields["type"] = "identity"
        eval_fields["severity"] = "medium"
        eval_fields["host"] = "active_directory"
    elif enum_type == ContainmentActionType.ROTATE_CREDENTIALS:
        eval_fields["user"] = sanitized_target
        eval_fields["action"] = "rotate"
        eval_fields["type"] = "identity"
        eval_fields["severity"] = "low"
        eval_fields["host"] = "active_directory"
    elif enum_type == ContainmentActionType.AUDIT_CLOUDTRAIL:
        eval_fields["resource"] = sanitized_target
        eval_fields["action"] = "audit"
        eval_fields["type"] = "cloudtrail"
        eval_fields["severity"] = "low"
        eval_fields["host"] = "aws_cloudtrail"
    elif enum_type == ContainmentActionType.KILL_PROCESS:
        eval_fields["process"] = sanitized_target
        eval_fields["action"] = "kill"
        eval_fields["type"] = "endpoint"
        eval_fields["severity"] = "high"
        eval_fields["host"] = "endpoint_manager"
    elif enum_type == ContainmentActionType.REVOKE_CREDENTIALS:
        eval_fields["user"] = sanitized_target
        eval_fields["action"] = "revoke"
        eval_fields["type"] = "identity"
        eval_fields["severity"] = "high"
        eval_fields["host"] = "active_directory"
    else:
        eval_fields["target"] = sanitized_target

    eval_fields["target"] = sanitized_target
    eval_fields["reason"] = sanitized_reason
    eval_fields["investigation_id"] = sanitized_investigation_id
    eval_fields["action_id"] = sanitized_action_id
    eval_fields["confidence"] = str(confidence)
    eval_fields["phase"] = str(phase)

    # Construct SPL
    eval_part = ", ".join(f'{k}="{v}"' for k, v in eval_fields.items())
    spl = f'| makeresults | eval {eval_part} | collect index=sentinel_actions'

    # Construct Reversal SPL if reversible
    reversal = None
    if not template_data.get("is_irreversible", False):
        rev_fields = {
            "reason": f"Analyst rollback of action {sanitized_action_id}",
            "investigation_id": sanitized_investigation_id,
            "action_id": sanitized_action_id,
            "severity": "informational",
        }
        if enum_type == ContainmentActionType.BLOCK_IP:
            rev_fields["ip"] = sanitized_target
            rev_fields["action"] = "unblock"
            rev_fields["type"] = "network"
            rev_fields["host"] = "firewall"
        elif enum_type == ContainmentActionType.ISOLATE_HOST:
            rev_fields["host"] = sanitized_target
            rev_fields["action"] = "rejoin"
            rev_fields["type"] = "endpoint"
        elif enum_type == ContainmentActionType.DISABLE_ACCOUNT:
            rev_fields["user"] = sanitized_target
            rev_fields["action"] = "enable"
            rev_fields["type"] = "identity"
            rev_fields["host"] = "active_directory"
        
        rev_fields["target"] = sanitized_target
        rev_eval = ", ".join(f'{k}="{v}"' for k, v in rev_fields.items())
        reversal = f'| makeresults | eval {rev_eval} | collect index=sentinel_actions'

    return spl, reversal


def validate_containment_spl(spl: str, action_type: Any) -> bool:
    """
    Validate containment SPL.
    """
    if not spl:
        return False
    if isinstance(action_type, str):
        try:
            enum_type = ContainmentActionType[action_type.upper()]
        except KeyError:
            return False
    else:
        enum_type = action_type

    if enum_type not in TEMPLATES:
        return False

    if "sentinel_actions" not in spl.lower():
        return False

    return True


def get_template_metadata(action_type: Any) -> dict:
    """
    Get template metadata (reversibility).
    """
    if isinstance(action_type, str):
        try:
            enum_type = ContainmentActionType[action_type.upper()]
        except KeyError:
            raise ValueError(f"Unknown action type: {action_type}")
    else:
        enum_type = action_type

    template_data = TEMPLATES.get(enum_type)
    if not template_data:
        raise ValueError(f"Unknown action type: {action_type}")

    return {
        "reversible": not template_data.get("is_irreversible", False)
    }
