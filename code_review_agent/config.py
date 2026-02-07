"""Configuration management for the code review agent."""

import os
from typing import Optional

import yaml


class Config:
    """Configuration class for the code review agent."""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config_path = config_path or "config.yaml"
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model = "claude-3-5-sonnet-20241022"
        self.load_config()

    def load_config(self):
        """Load configuration from YAML file if it exists."""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                config_data = yaml.safe_load(f)
                if config_data:
                    for key, value in config_data.items():
                        setattr(self, key, value)
