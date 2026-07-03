from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SessionRole(str, Enum):
    ANONYMOUS = "anonymous"
    LOW_PRIVILEGE = "low_privilege"
    HIGH_PRIVILEGE = "high_privilege"
    ADMIN = "admin"


class AuthToken(BaseModel):
    type: str
    value: str
    expires_at: Optional[datetime] = None
    source: str


class BrowserSession(BaseModel):
    session_id: str
    role: SessionRole
    cookies: Dict[str, str] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    tokens: List[AuthToken] = Field(default_factory=list)
    storage: Dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_used: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    artifact_ref: Optional[str] = None


class SessionPool(BaseModel):
    sessions: Dict[str, BrowserSession] = Field(default_factory=dict)
    active_session_id: Optional[str] = None

