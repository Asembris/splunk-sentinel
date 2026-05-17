"""
containment_templates.py
------------------------
Catalog of safe, predefined SPL templates for containment actions.
Ensures that all remediation actions follow a strictly controlled syntax
and target only the permitted sentinel_actions index.
"""

from typing import Dict, Any
from app.models.containment import ContainmentActionType


TEMPLATES: Dict[ContainmentActionType, Dict[str, str]] = {
    ContainmentActionType.BLOCK_IP: {
        "title": "Block Malicious IP",
        "description": "Blacklist a source IP across the enterprise security boundary.",
        "spl": '| makeresults | eval ip="{{target}}", action="block", type="network", severity="high", reason="Sentinel investigation findings" | collect index=sentinel_actions',
        "reversal": '| makeresults | eval ip="{{target}}", action="unblock", type="network", reason="Sentinel analyst rollback" | collect index=sentinel_actions',
    },
    ContainmentActionType.ISOLATE_HOST: {
        "title": "Isolate Endpoint",
        "description": "Sever network connectivity for the affected host except for management and Sentinel traffic.",
        "spl": '| makeresults | eval host="{{target}}", action="isolate", type="endpoint", severity="critical" | collect index=sentinel_actions',
        "reversal": '| makeresults | eval host="{{target}}", action="rejoin", type="endpoint", reason="Post-investigation restoration" | collect index=sentinel_actions',
    },
    ContainmentActionType.KILL_PROCESS: {
        "title": "Terminate Malicious Process",
        "description": "Remotely terminate a process by name or PID.",
        "spl": '| makeresults | eval process="{{target}}", action="kill" | collect index=sentinel_actions',
        "reversal": None,  # Process termination is irreversible
    },
    ContainmentActionType.REVOKE_CREDENTIALS: {
        "title": "Revoke User Session",
        "description": "Invalidate all active sessions and force password reset for the compromised account.",
        "spl": '| makeresults | eval user="{{target}}", action="revoke", type="identity" | collect index=sentinel_actions',
        "reversal": None,  # Credential revocation is effectively irreversible via SPL
    },
}


def render_template(template_type: ContainmentActionType, target: str, context: Dict[str, Any] = None) -> Dict[str, str]:
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
        "description": template_data["description"]
    }
