"""
Parse LLM responses into structured Issue objects.

Handles various response formats and extracts severity, description, fixes, OWASP/CWE mappings.
"""

import re
from typing import List, Optional
from .models import Issue, Severity, ReviewCategory, RiskLevel


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
        
        # First line is description (may include line number, OWASP, CWE)
        # Format: "Issue description (line X) | OWASP A03:2021, CWE-89"
        description = lines[0]
        line_number = self._extract_line_number(description)
        owasp_id = self._extract_owasp_id(description)
        cwe_id = self._extract_cwe_id(description)
        
        # Remove line number and OWASP/CWE from description
        description = re.sub(r"\(line \d+\)", "", description)
        # Remove | OWASP... or | CWE-... patterns
        description = re.sub(r"\|\s*OWASP[^,\n|]+(?:,\s*CWE-\d+)?", "", description)
        description = re.sub(r"\|\s*CWE-\d+", "", description)
        description = description.strip()
        
        # Extract other fields
        fix_suggestion = None
        regulation_reference = None
        code_snippet = None
        impact = None
        risk_level = self._severity_to_risk_level(severity)
        
        in_code_block = False
        code_lines = []
        
        for line in lines[1:]:
            # Check for risk/impact
            if line.strip().startswith("Risk:"):
                impact = line.split(":", 1)[1].strip()
            
            # Check for fix suggestion
            elif line.strip().startswith("Fix:"):
                # Next code block is the fix
                in_code_block = "fix"
            
            # Check for regulation reference
            elif line.strip().startswith("Regulation:"):
                regulation_reference = line.split(":", 1)[1].strip()
            
            # Check for code blocks
            elif "```python" in line or "```" in line:
                if "```python" in line or (in_code_block and "```" in line):
                    if in_code_block == "fix":
                        # Closing fix block
                        fix_suggestion = "\n".join(code_lines)
                        in_code_block = False
                        code_lines = []
                    elif "```" in line and in_code_block:
                        # Closing other block
                        code_snippet = "\n".join(code_lines)
                        in_code_block = False
                        code_lines = []
                    else:
                        # Opening new block
                        in_code_block = True
                        code_lines = []
            
            elif in_code_block:
                code_lines.append(line)
        
        return Issue(
            severity=severity,
            description=description,
            line_number=line_number,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            regulation_reference=regulation_reference,
            owasp_id=owasp_id,
            cwe_id=cwe_id,
            risk_level=risk_level,
            impact=impact
        )
    
    def _extract_line_number(self, text: str) -> Optional[int]:
        """Extract line number from text like 'Issue (line 45)'."""
        
        match = re.search(r"\(line (\d+)\)", text)
        if match:
            return int(match.group(1))
        return None
    
    def _extract_owasp_id(self, text: str) -> Optional[str]:
        """Extract OWASP ID from text like 'OWASP A03:2021 - Injection'."""
        
        match = re.search(r"OWASP\s+(A\d{2}:\d{4}(?:\s*-\s*[^,|\n]+)?)", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None
    
    def _extract_cwe_id(self, text: str) -> Optional[str]:
        """Extract CWE ID from text like 'CWE-89'."""
        
        match = re.search(r"CWE-(\d+)", text, re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return None
    
    def _severity_to_risk_level(self, severity: Severity) -> RiskLevel:
        """Map severity to risk level."""
        
        mapping = {
            Severity.CRITICAL: RiskLevel.CRITICAL,
            Severity.HIGH: RiskLevel.HIGH,
            Severity.MEDIUM: RiskLevel.MEDIUM,
            Severity.LOW: RiskLevel.LOW,
            Severity.INFO: RiskLevel.LOW,
        }
        return mapping.get(severity, RiskLevel.MEDIUM)
