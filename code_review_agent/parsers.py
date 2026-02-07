"""Response parsing logic for Claude API responses."""

import json
from typing import List

from code_review_agent.models import Issue, ReviewResult


def parse_review_response(response_text: str, file_path: str) -> ReviewResult:
    """Parse Claude's review response into ReviewResult.
    
    Args:
        response_text: Raw response from Claude API
        file_path: Path to the reviewed file
        
    Returns:
        ReviewResult object with parsed data
    """
    raise NotImplementedError("Parser implementation pending")


def parse_issues(issues_data: List[dict]) -> List[Issue]:
    """Convert parsed issues into Issue models.
    
    Args:
        issues_data: List of issue dictionaries
        
    Returns:
        List of Issue objects
    """
    return [Issue(**issue) for issue in issues_data]
