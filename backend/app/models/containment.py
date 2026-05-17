from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ContainmentStatus(str, Enum):
    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SKIPPED = "SKIPPED"


class ContainmentActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    KILL_PROCESS = "KILL_PROCESS"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    ROTATE_CREDENTIALS = "ROTATE_CREDENTIALS"
    AUDIT_CLOUDTRAIL = "AUDIT_CLOUDTRAIL"
    GENERIC_SPL = "GENERIC_SPL"


class ContainmentAction(BaseModel):
    id: str
    type: ContainmentActionType
    title: str
    description: str
    target: str  # e.g., IP, Hostname, User
    containment_spl: str
    reversal_spl: Optional[str] = None
    status: ContainmentStatus = ContainmentStatus.PENDING
    error: Optional[str] = None
    executed_at: Optional[datetime] = None
    executed_by: Optional[str] = "Sentinel Engine"
    splunk_sid: Optional[str] = None
    is_irreversible: bool = False


class ContainmentPhase(BaseModel):
    name: str
    description: str
    actions: List[ContainmentAction]
    status: ContainmentStatus = ContainmentStatus.PENDING


class ContainmentPlan(BaseModel):
    investigation_id: str
    phases: List[ContainmentPhase]
    status: ContainmentStatus = ContainmentStatus.PENDING
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def update_status(self):
        """Update plan status based on phase statuses."""
        if any(p.status == ContainmentStatus.EXECUTING for p in self.phases):
            self.status = ContainmentStatus.EXECUTING
        elif all(p.status in [ContainmentStatus.EXECUTED, ContainmentStatus.SKIPPED] for p in self.phases):
            self.status = ContainmentStatus.EXECUTED
        elif any(p.status == ContainmentStatus.FAILED for p in self.phases):
            self.status = ContainmentStatus.FAILED
        else:
            self.status = ContainmentStatus.PENDING
