from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator


class ContainmentStatus(str, Enum):
    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SKIPPED = "SKIPPED"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


class ContainmentActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_HOST = "ISOLATE_HOST"
    KILL_PROCESS = "KILL_PROCESS"
    REVOKE_CREDENTIALS = "REVOKE_CREDENTIALS"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    ROTATE_CREDENTIALS = "ROTATE_CREDENTIALS"
    AUDIT_CLOUDTRAIL = "AUDIT_CLOUDTRAIL"
    GENERIC_SPL = "GENERIC_SPL"


# Test Compatibility Mappings
ActionType = ContainmentActionType
ActionStatus = ContainmentStatus
PlanStatus = ContainmentStatus


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ContainmentAction(BaseModel):
    id: str
    action_id: str = ""
    type: ContainmentActionType
    title: str = "Test Action"
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
    rolled_back_at: Optional[str] = None
    rollback_result: Optional[Dict[str, Any]] = None
    
    # Test Compatibility Fields
    phase: int = 1
    risk_level: RiskLevel = RiskLevel.LOW
    reversible: bool = True

    @model_validator(mode="before")
    @classmethod
    def handle_compatibility(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync id and action_id
            if "action_id" in data and "id" not in data:
                data["id"] = data["action_id"]
            elif "id" in data and "action_id" not in data:
                data["action_id"] = data["id"]
            
            # Sync title
            if "title" not in data:
                data["title"] = "Test Action"
            
            # Sync is_irreversible and reversible
            if "reversible" in data and "is_irreversible" not in data:
                data["is_irreversible"] = not data["reversible"]
            elif "is_irreversible" in data and "reversible" not in data:
                data["reversible"] = not data["is_irreversible"]
        return data


class ContainmentPhase(BaseModel):
    name: str = ""
    description: str = ""
    actions: List[ContainmentAction]
    status: ContainmentStatus = ContainmentStatus.PENDING
    
    # Test Compatibility Fields
    phase: int = 1
    label: str = ""
    timeframe: str = ""

    @model_validator(mode="before")
    @classmethod
    def handle_compatibility(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "label" in data and "name" not in data:
                data["name"] = data["label"]
            elif "name" in data and "label" not in data:
                data["label"] = data["name"]
            
            if "timeframe" in data and "description" not in data:
                data["description"] = data["timeframe"]
            elif "description" in data and "timeframe" not in data:
                data["timeframe"] = data["description"]
        return data


class ContainmentPlan(BaseModel):
    investigation_id: str
    phases: List[ContainmentPhase]
    status: ContainmentStatus = ContainmentStatus.PENDING
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Test Compatibility Fields
    plan_id: str = ""
    classification: str = "UNKNOWN"
    confidence: float = 1.0
    last_modified_at: Optional[datetime] = None
    edit_history: List[Any] = Field(default_factory=list)
    analyst_reviewed: bool = False
    analyst_edited: bool = False

    @model_validator(mode="before")
    @classmethod
    def handle_compatibility(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "last_modified_at" in data and "updated_at" not in data:
                data["updated_at"] = data["last_modified_at"]
            elif "updated_at" in data and "last_modified_at" not in data:
                data["last_modified_at"] = data["updated_at"]
            if "plan_id" in data and "investigation_id" not in data:
                data["investigation_id"] = data["plan_id"]
        return data

    @property
    def total_actions(self) -> int:
        return sum(len(p.actions) for p in self.phases)

    @property
    def executed_actions(self) -> int:
        return sum(1 for p in self.phases for a in p.actions if a.status == ContainmentStatus.EXECUTED)

    @property
    def failed_actions(self) -> int:
        return sum(1 for p in self.phases for a in p.actions if a.status == ContainmentStatus.FAILED)

    @property
    def skipped_actions(self) -> int:
        return sum(1 for p in self.phases for a in p.actions if a.status == ContainmentStatus.SKIPPED)

    @property
    def rolled_back_actions(self) -> int:
        return sum(1 for p in self.phases for a in p.actions if a.status == ContainmentStatus.ROLLED_BACK)

    def update_status(self):
        """Update plan status based on phase statuses."""
        if any(p.status == ContainmentStatus.EXECUTING for p in self.phases):
            self.status = ContainmentStatus.EXECUTING
        elif all(p.status in [ContainmentStatus.EXECUTED, ContainmentStatus.SKIPPED, ContainmentStatus.COMPLETE] for p in self.phases):
            self.status = ContainmentStatus.EXECUTED
        elif any(p.status == ContainmentStatus.FAILED for p in self.phases):
            self.status = ContainmentStatus.FAILED
        else:
            self.status = ContainmentStatus.PENDING
