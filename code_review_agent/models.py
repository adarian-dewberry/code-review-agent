"""Data models for the code review agent."""

from typing import List, Optional

from pydantic import BaseModel, Field


class Issue(BaseModel):
    """Represents a single code review issue."""

    severity: str = Field(..., description="Issue severity: critical, warning, info")
    category: str = Field(..., description="Issue category: security, performance, logic, style")
    line: Optional[int] = Field(None, description="Line number where issue occurs")
    description: str = Field(..., description="Detailed description of the issue")
    suggestion: Optional[str] = Field(None, description="Suggested fix for the issue")


class ReviewResult(BaseModel):
    """Represents the result of a code review."""

    file_path: str = Field(..., description="Path to the reviewed file")
    issues: List[Issue] = Field(default_factory=list, description="List of found issues")
    summary: str = Field(..., description="Summary of the review")
    score: Optional[float] = Field(None, description="Overall quality score 0-100")
