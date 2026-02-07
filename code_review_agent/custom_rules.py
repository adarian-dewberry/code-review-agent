"""Custom rules engine for organizational policy enforcement.

Loads and validates custom rules from YAML configuration.
"""

import re
from pathlib import Path
from typing import Optional
import yaml
from pydantic import BaseModel, Field

from .models import Issue, Severity, RiskLevel


class RulePattern(BaseModel):
    """Pattern matching configuration for a rule."""
    
    patterns: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)


class CustomRule(BaseModel):
    """Organizational policy rule definition."""
    
    id: str
    title: str
    severity: str
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    description: str
    match: RulePattern


class CustomRulesEngine:
    """
    Loads and enforces custom organizational rules.
    
    Rules are defined in YAML format with pattern matching.
    Violations are flagged during code review.
    """
    
    def __init__(self, rules_path: Optional[Path] = None):
        """
        Initialize rules engine.
        
        Args:
            rules_path: Path to custom_rules.yaml file
        """
        
        self.rules: list[CustomRule] = []
        
        if rules_path is None:
            # Default to config/custom_rules.yaml
            rules_path = Path(__file__).parent.parent / "config" / "custom_rules.yaml"
        
        if rules_path.exists():
            self.load_rules(rules_path)
    
    def load_rules(self, rules_path: Path) -> None:
        """Load and parse custom rules from YAML file."""
        
        with open(rules_path) as f:
            data = yaml.safe_load(f)
        
        if not data or "rules" not in data:
            return
        
        for rule_data in data["rules"]:
            # Convert match patterns to RulePattern model
            match_data = rule_data.get("match", {})
            rule_data["match"] = RulePattern(**match_data)
            
            rule = CustomRule(**rule_data)
            self.rules.append(rule)
    
    def check_code(self, code: str, file_path: Optional[str] = None) -> list[Issue]:
        """
        Check code against all custom rules.
        
        Args:
            code: Source code to check
            file_path: Optional file path for context
        
        Returns:
            List of Issues for rule violations
        """
        
        violations = []
        
        for rule in self.rules:
            # Check pattern matches
            for pattern in rule.match.patterns:
                if pattern in code:
                    violations.append(self._create_issue(rule, pattern, file_path))
                    break  # Only report once per rule
            
            # Check regex matches
            if not violations or violations[-1].description != rule.description:
                for regex_pattern in rule.match.regex:
                    if re.search(regex_pattern, code, re.MULTILINE):
                        violations.append(self._create_issue(rule, f"regex: {regex_pattern}", file_path))
                        break
        
        return violations
    
    def _create_issue(self, rule: CustomRule, matched_pattern: str, file_path: Optional[str]) -> Issue:
        """Convert rule violation to Issue model."""
        
        # Map severity string to enum
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }
        
        severity = severity_map.get(rule.severity.upper(), Severity.MEDIUM)
        
        # Map severity to risk level
        risk_map = {
            Severity.CRITICAL: RiskLevel.CRITICAL,
            Severity.HIGH: RiskLevel.HIGH,
            Severity.MEDIUM: RiskLevel.MEDIUM,
            Severity.LOW: RiskLevel.LOW,
            Severity.INFO: RiskLevel.LOW,
        }
        
        risk_level = risk_map[severity]
        
        # Build description with context
        description = f"[{rule.id}] {rule.title}: {rule.description}"
        if file_path:
            description = f"{description} (in {file_path})"
        
        return Issue(
            severity=severity,
            description=description,
            line_number=None,  # Pattern matching doesn't provide line numbers
            code_snippet=f"Matched pattern: {matched_pattern}",
            fix_suggestion=f"Review code for compliance with {rule.id}",
            cwe_id=rule.cwe_id,
            owasp_id=rule.owasp_id,
            risk_level=risk_level,
            impact=f"Violation of organizational policy: {rule.title}"
        )
