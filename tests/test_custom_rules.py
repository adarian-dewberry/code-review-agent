"""Tests for custom rules engine."""

import tempfile
from pathlib import Path
import pytest
import yaml

from code_review_agent.custom_rules import (
    CustomRulesEngine, CustomRule, RulePattern
)
from code_review_agent.models import Severity, RiskLevel


class TestCustomRulesEngine:
    """Test custom rules loading and enforcement."""
    
    def test_load_default_rules(self):
        """Test loading default custom_rules.yaml."""
        engine = CustomRulesEngine()
        
        # Should load rules from config/custom_rules.yaml
        assert len(engine.rules) > 0
        
        # Verify rule structure
        rule = engine.rules[0]
        assert rule.id == "CR-001"
        assert rule.title == "Disallow eval()"
        assert rule.severity == "HIGH"
    
    def test_load_from_custom_path(self):
        """Test loading rules from custom path."""
        # Create temporary rules file
        rules_data = {
            "rules": [
                {
                    "id": "TEST-001",
                    "title": "Test Rule",
                    "severity": "MEDIUM",
                    "description": "Test description",
                    "match": {
                        "patterns": ["test_pattern"]
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rules_data, f)
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            assert len(engine.rules) == 1
            assert engine.rules[0].id == "TEST-001"
        finally:
            rules_path.unlink()
    
    def test_empty_rules_file(self):
        """Test handling empty rules file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            assert len(engine.rules) == 0
        finally:
            rules_path.unlink()
    
    def test_check_code_pattern_match(self):
        """Test pattern matching in code."""
        rules_data = {
            "rules": [
                {
                    "id": "EVAL-001",
                    "title": "No eval()",
                    "severity": "HIGH",
                    "cwe_id": "CWE-95",
                    "description": "eval() is dangerous",
                    "match": {
                        "patterns": ["eval("]
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rules_data, f)
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            
            # Test code with violation
            code = "result = eval(user_input)"
            violations = engine.check_code(code)
            
            assert len(violations) == 1
            assert violations[0].severity == Severity.HIGH
            assert "EVAL-001" in violations[0].description
            assert violations[0].cwe_id == "CWE-95"
        finally:
            rules_path.unlink()
    
    def test_check_code_regex_match(self):
        """Test regex matching in code."""
        rules_data = {
            "rules": [
                {
                    "id": "SECRET-001",
                    "title": "No hardcoded secrets",
                    "severity": "CRITICAL",
                    "owasp_id": "A02:2021",
                    "description": "Use secrets manager",
                    "match": {
                        "regex": [
                            "api_key\\s*=\\s*['\"][A-Za-z0-9_-]{16,}['\"]"
                        ]
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rules_data, f)
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            
            # Test code with violation
            code = 'api_key = "sk-1234567890abcdef"'
            violations = engine.check_code(code)
            
            assert len(violations) == 1
            assert violations[0].severity == Severity.CRITICAL
            assert violations[0].owasp_id == "A02:2021"
            assert violations[0].risk_level == RiskLevel.CRITICAL
        finally:
            rules_path.unlink()
    
    def test_check_code_no_violations(self):
        """Test code without violations."""
        rules_data = {
            "rules": [
                {
                    "id": "TEST-001",
                    "title": "Test",
                    "severity": "LOW",
                    "description": "Test rule",
                    "match": {
                        "patterns": ["dangerous_function("]
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rules_data, f)
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            
            # Test safe code
            code = "result = safe_function(data)"
            violations = engine.check_code(code)
            
            assert len(violations) == 0
        finally:
            rules_path.unlink()
    
    def test_multiple_rules(self):
        """Test checking against multiple rules."""
        rules_data = {
            "rules": [
                {
                    "id": "RULE-001",
                    "title": "Rule 1",
                    "severity": "HIGH",
                    "description": "First rule",
                    "match": {
                        "patterns": ["eval("]
                    }
                },
                {
                    "id": "RULE-002",
                    "title": "Rule 2",
                    "severity": "MEDIUM",
                    "description": "Second rule",
                    "match": {
                        "patterns": ["exec("]
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rules_data, f)
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            
            # Test code with both violations
            code = "eval(x); exec(y)"
            violations = engine.check_code(code)
            
            assert len(violations) == 2
            assert violations[0].severity == Severity.HIGH
            assert violations[1].severity == Severity.MEDIUM
        finally:
            rules_path.unlink()
    
    def test_severity_to_risk_mapping(self):
        """Test severity correctly maps to risk level."""
        rules_data = {
            "rules": [
                {
                    "id": "CRIT",
                    "title": "Critical",
                    "severity": "CRITICAL",
                    "description": "Critical rule",
                    "match": {"patterns": ["crit"]}
                },
                {
                    "id": "HIGH",
                    "title": "High",
                    "severity": "HIGH",
                    "description": "High rule",
                    "match": {"patterns": ["high"]}
                },
                {
                    "id": "MED",
                    "title": "Medium",
                    "severity": "MEDIUM",
                    "description": "Medium rule",
                    "match": {"patterns": ["med"]}
                },
                {
                    "id": "LOW",
                    "title": "Low",
                    "severity": "LOW",
                    "description": "Low rule",
                    "match": {"patterns": ["low"]}
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(rules_data, f)
            rules_path = Path(f.name)
        
        try:
            engine = CustomRulesEngine(rules_path)
            
            violations = engine.check_code("crit high med low")
            
            assert violations[0].risk_level == RiskLevel.CRITICAL
            assert violations[1].risk_level == RiskLevel.HIGH
            assert violations[2].risk_level == RiskLevel.MEDIUM
            assert violations[3].risk_level == RiskLevel.LOW
        finally:
            rules_path.unlink()
