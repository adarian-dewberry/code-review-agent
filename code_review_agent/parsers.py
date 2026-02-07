"""
Parse LLM responses into structured Issue objects.

Handles various response formats and extracts severity, description, fixes.
"""

import re
from typing import List, Optional
from .models import Issue, Severity, ReviewCategory


class ReviewParser:
    """Parse Claude's review responses into structured data."""
    
    # Severity markers
    SEVERITY_MARKERS = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    
    def parse(self, response_text: str, category: str) -> ReviewCategory:
        """
        Parse review response into ReviewCategory.
        
        Expected format:
        ## CRITICAL
        - Issue description (line X)
          Risk: Impact details
          Fix: ```python
          suggested code
        ```
        
        ## HIGH
        ...
        """
        
        review = ReviewCategory(category=category)
        
        # Split into sections by severity
        sections = self._split_by_severity(response_text)
        
        for severity_str, content in sections.items():
            severity = self.SEVERITY_MARKERS.get(severity_str)
            if not severity:
                continue
            
            # Parse issues from this severity section
            issues = self._parse_issues(content, severity)
            for issue in issues:
                review.add_issue(issue)
        
        return review
    
    def _split_by_severity(self, text: str) -> dict[str, str]:
        """Split text into sections by severity headers."""
        
        sections = {}
        current_severity = None
        current_content = []
        
        for line in text.split("\n"):
            # Check if this is a severity header
            severity_match = re.match(r"^##\s+(CRITICAL|HIGH|MEDIUM|LOW|INFO)", line)
            
            if severity_match:
                # Save previous section
                if current_severity and current_content:
                    sections[current_severity] = "\n".join(current_content)
                
                # Start new section
                current_severity = severity_match.group(1)
                current_content = []
            else:
                if current_severity:
                    current_content.append(line)
        
        # Save last section
        if current_severity and current_content:
            sections[current_severity] = "\n".join(current_content)
        
        return sections
    
    def _parse_issues(self, content: str, severity: Severity) -> List[Issue]:
        """Parse individual issues from severity section."""
        
        issues = []
        
        # Split by bullet points
        issue_blocks = re.split(r"\n- ", content)
        
        for block in issue_blocks:
            if not block.strip():
                continue
            
            issue = self._parse_issue_block(block, severity)
            if issue:
                issues.append(issue)
        
        return issues
    
    def _parse_issue_block(self, block: str, severity: Severity) -> Optional[Issue]:
        """Parse a single issue block."""
        
        lines = block.strip().split("\n")
        if not lines:
            return None
        
        # First line is description (may include line number)
        description = lines[0]
        line_number = self._extract_line_number(description)
        
        # Remove line number from description
        description = re.sub(r"\(line \d+\)", "", description).strip()
        
        # Extract other fields
        fix_suggestion = None
        regulation_reference = None
        code_snippet = None
        
        in_code_block = False
        code_lines = []
        
        for line in lines[1:]:
            # Check for fix suggestion
            if line.strip().startswith("Fix:"):
                # Next code block is the fix
                in_code_block = "fix"
            
            # Check for regulation reference
            elif line.strip().startswith("Regulation:"):
                regulation_reference = line.split(":", 1)[1].strip()
            
            # Check for code blocks
            elif "```python" in line:
                in_code_block = True
                code_lines = []
            
            elif "```" in line and in_code_block:
                if in_code_block == "fix":
                    fix_suggestion = "\n".join(code_lines)
                else:
                    code_snippet = "\n".join(code_lines)
                in_code_block = False
                code_lines = []
            
            elif in_code_block:
                code_lines.append(line)
        
        return Issue(
            severity=severity,
            description=description,
            line_number=line_number,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            regulation_reference=regulation_reference
        )
    
    def _extract_line_number(self, text: str) -> Optional[int]:
        """Extract line number from text like 'Issue (line 45)'."""
        
        match = re.search(r"\(line (\d+)\)", text)
        if match:
            return int(match.group(1))
        return None
