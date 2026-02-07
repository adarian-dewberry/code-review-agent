"""Core code review agent implementation."""

from code_review_agent.models import ReviewResult


class CodeReviewAgent:
    """Performs automated code reviews using Claude AI."""

    def __init__(self, config=None):
        """Initialize the code review agent.
        
        Args:
            config: Configuration object for the agent
        """
        self.config = config

    def review(self, code: str, review_type: str = "general") -> ReviewResult:
        """Review code and return findings.
        
        Args:
            code: The code to review
            review_type: Type of review (general, security, performance, etc.)
            
        Returns:
            ReviewResult object with findings
        """
        raise NotImplementedError("This method will be implemented with Claude API")
