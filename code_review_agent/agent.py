"""
Core code review agent.

Orchestrates multi-pass review using Claude API.
"""

from pathlib import Path
from typing import Optional
import anthropic

from .config import Config
from .models import ReviewResult, ReviewCategory, ReviewSummary, ReviewRecommendation, Severity
from .parsers import ReviewParser


class CodeReviewAgent:
    """
    Multi-pass code review agent.
    
    Performs four review passes:
    1. Security (prompt injection, data leaks, auth bypass)
    2. Logic (edge cases, error handling, race conditions)
    3. Performance (scalability, efficiency, resource usage)
    4. Compliance (GDPR, audit trails, data minimization)
    """
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize agent with configuration."""
        
        self.config = config or Config.load()
        self.config.validate_api_key()
        
        self.client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)
        self.parser = ReviewParser()
    
    def review(self, code: str, file_path: Optional[str] = None) -> ReviewResult:
        """
        Run complete multi-pass review on code.
        
        Args:
            code: Source code to review
            file_path: Optional file path for context
        
        Returns:
            ReviewResult with findings from all categories
        """
        
        categories = {}
        
        # Run enabled review passes
        for category in self.config.review.enabled_categories:
            if category == "security":
                categories["security"] = self._security_review(code, file_path)
            
            elif category == "logic":
                categories["logic"] = self._logic_review(code, file_path)
            
            elif category == "performance":
                categories["performance"] = self._performance_review(code, file_path)
            
            elif category == "compliance":
                categories["compliance"] = self._compliance_review(code, file_path)
        
        # Generate summary
        summary = self._generate_summary(categories)
        
        return ReviewResult(
            file_path=file_path,
            security=categories.get("security", ReviewCategory(category="security")),
            logic=categories.get("logic", ReviewCategory(category="logic")),
            performance=categories.get("performance", ReviewCategory(category="performance")),
            compliance=categories.get("compliance", ReviewCategory(category="compliance")),
            summary=summary
        )
    
    def _security_review(self, code: str, file_path: Optional[str]) -> ReviewCategory:
        """Perform security-focused review pass."""
        
        prompt = self._load_prompt("security")
        response = self._call_claude(prompt, code, file_path)
        return self.parser.parse(response, "security")
    
    def _logic_review(self, code: str, file_path: Optional[str]) -> ReviewCategory:
        """Perform logic/correctness review pass."""
        
        prompt = self._load_prompt("logic")
        response = self._call_claude(prompt, code, file_path)
        return self.parser.parse(response, "logic")
    
    def _performance_review(self, code: str, file_path: Optional[str]) -> ReviewCategory:
        """Perform performance/scalability review pass."""
        
        prompt = self._load_prompt("performance")
        response = self._call_claude(prompt, code, file_path)
        return self.parser.parse(response, "performance")
    
    def _compliance_review(self, code: str, file_path: Optional[str]) -> ReviewCategory:
        """Perform compliance review pass (GDPR, CCPA, EU AI Act)."""
        
        prompt = self._load_prompt("compliance")
        response = self._call_claude(prompt, code, file_path)
        return self.parser.parse(response, "compliance")
    
    def _load_prompt(self, category: str) -> str:
        """Load prompt template for category."""
        
        prompt_path = self.config.prompt_dir / f"{category}.md"
        
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt not found: {prompt_path}")
        
        return prompt_path.read_text()
    
    def _call_claude(self, prompt: str, code: str, file_path: Optional[str]) -> str:
        """Call Claude API with prompt and code."""
        
        # Add file context if provided
        context = ""
        if file_path:
            context = f"File: {file_path}\n\n"
        
        full_prompt = f"{prompt}\n\n{context}# Code to Review\n```python\n{code}\n```"
        
        response = self.client.messages.create(
            model=self.config.model.name,
            max_tokens=self.config.model.max_tokens,
            temperature=self.config.model.temperature,
            messages=[{
                "role": "user",
                "content": full_prompt
            }]
        )
        
        return response.content[0].text
    
    def _generate_summary(self, categories: dict[str, ReviewCategory]) -> ReviewSummary:
        """Generate executive summary from all review categories."""
        
        critical_count = sum(cat.critical_count for cat in categories.values())
        high_count = sum(cat.high_count for cat in categories.values())
        
        medium_count = sum(
            len([i for i in cat.issues if i.severity == Severity.MEDIUM])
            for cat in categories.values()
        )
        
        low_count = sum(
            len([i for i in cat.issues if i.severity == Severity.LOW])
            for cat in categories.values()
        )
        
        info_count = sum(
            len([i for i in cat.issues if i.severity == Severity.INFO])
            for cat in categories.values()
        )
        
        # Determine recommendation
        if critical_count > 0:
            recommendation = ReviewRecommendation.DO_NOT_MERGE
        elif high_count > 3:
            recommendation = ReviewRecommendation.MERGE_WITH_CAUTION
        else:
            recommendation = ReviewRecommendation.APPROVED
        
        # Extract top issues (all critical + top 3 high)
        top_issues = []
        
        for cat in categories.values():
            for issue in cat.issues:
                if issue.severity == Severity.CRITICAL:
                    top_issues.append(f"[{cat.category.upper()}] {issue.description}")
        
        high_issues = []
        for cat in categories.values():
            for issue in cat.issues:
                if issue.severity == Severity.HIGH:
                    high_issues.append(f"[{cat.category.upper()}] {issue.description}")
        
        top_issues.extend(high_issues[:3])
        
        return ReviewSummary(
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            recommendation=recommendation,
            top_issues=top_issues
        )
