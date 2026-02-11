"""Pydantic models for CROW data structures."""
from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, Field


class BaseRecord(BaseModel):
    model_config = {"extra": "allow"} 

    plugin: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class WHOISRecord(BaseRecord):
    domain: str
    registrant: Optional[str] = None
    emails: List[str] = Field(default_factory=list)
    creation_date: Optional[str] = None
    name_servers: List[str] = Field(default_factory=list)


class PluginOutput(BaseModel):
    plugin: str
    results: List[Any] = Field(default_factory=list) 
    errors: List[str] = Field(default_factory=list)
