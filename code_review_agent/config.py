"""Configuration management for code review agent.

Loads settings from config.yaml and environment variables.
"""

import os
from pathlib import Path
from typing import Optional
import yaml
from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    """LLM model configuration."""
    
    name: str = Field(default="claude-sonnet-4-20250514")
    max_tokens: int = Field(default=4000, ge=1000, le=8000)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)


class ReviewConfig(BaseModel):
    """Review behavior configuration."""
    
    enabled_categories: list[str] = Field(
        default_factory=lambda: ["security", "logic", "performance", "compliance"]
    )
    fail_on_critical: bool = Field(default=True)
    fail_on_high: bool = Field(default=False)
    max_issues_per_category: int = Field(default=20)


class Config(BaseModel):
    """Main application configuration."""
    
    model: ModelConfig = Field(default_factory=ModelConfig)
    review: ReviewConfig = Field(default_factory=ReviewConfig)
    anthropic_api_key: Optional[str] = Field(default=None)
    prompt_dir: Path = Field(default=Path(__file__).parent / "prompts")
    
    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Config":
        """
        Load configuration from file and environment.
        
        Priority:
        1. Environment variables
        2. Config file
        3. Defaults
        """
        
        # Load from file if provided
        config_data = {}
        if config_path:
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}
        
        # Override with environment variables
        if api_key := os.getenv("ANTHROPIC_API_KEY"):
            config_data["anthropic_api_key"] = api_key
        
        return cls(**config_data)
    
    def validate_api_key(self) -> None:
        """Ensure API key is configured."""
        if not self.anthropic_api_key:
            raise ValueError(
                "Anthropic API key not configured. Set ANTHROPIC_API_KEY "
                "environment variable or add to config.yaml"
            )
