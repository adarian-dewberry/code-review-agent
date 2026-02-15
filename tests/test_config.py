"""Tests for configuration management."""

import os
import tempfile

import pytest
import yaml  # type: ignore

from code_review_agent.config import Config, ModelConfig, ReviewConfig


class TestModelConfig:
    """Test ModelConfig validation and defaults."""

    def test_default_model(self):
        """Test default model configuration."""
        config = ModelConfig()
        assert config.name == "claude-3-5-sonnet-20241022"
        assert config.max_tokens == 4000
        assert config.temperature == 0.0

    def test_custom_model(self):
        """Test custom model configuration."""
        config = ModelConfig(name="custom-model", max_tokens=8000, temperature=0.5)
        assert config.name == "custom-model"
        assert config.max_tokens == 8000
        assert config.temperature == 0.5

    def test_invalid_max_tokens(self):
        """Test validation of max_tokens range."""
        with pytest.raises(ValueError):
            ModelConfig(max_tokens=500)  # Below minimum

        with pytest.raises(ValueError):
            ModelConfig(max_tokens=10000)  # Above maximum

    def test_invalid_temperature(self):
        """Test validation of temperature range."""
        with pytest.raises(ValueError):
            ModelConfig(temperature=-0.1)

        with pytest.raises(ValueError):
            ModelConfig(temperature=1.5)


class TestReviewConfig:
    """Test ReviewConfig validation and defaults."""

    def test_default_categories(self):
        """Test default enabled categories."""
        config = ReviewConfig()
        assert config.enabled_categories == [
            "security",
            "logic",
            "performance",
            "compliance",
        ]

    def test_default_exclusions(self):
        """Test default file exclusion patterns."""
        config = ReviewConfig()
        assert "*.min.js" in config.exclude_patterns
        assert ".env" in config.exclude_patterns
        assert "node_modules/**" in config.exclude_patterns
        assert ".venv/**" in config.exclude_patterns

    def test_custom_categories(self):
        """Test custom category configuration."""
        config = ReviewConfig(enabled_categories=["security", "performance"])
        assert len(config.enabled_categories) == 2
        assert "logic" not in config.enabled_categories

    def test_fail_on_severity(self):
        """Test fail-on-severity flags."""
        config = ReviewConfig()
        assert config.fail_on_critical is True
        assert config.fail_on_high is False


class TestConfig:
    """Test main Config class."""

    def test_default_config(self):
        """Test default configuration loading."""
        # Set API key via environment
        os.environ["ANTHROPIC_API_KEY"] = "test-key-123"

        config = Config.load()
        assert config.anthropic_api_key == "test-key-123"
        assert isinstance(config.model, ModelConfig)
        assert isinstance(config.review, ReviewConfig)

        # Cleanup
        del os.environ["ANTHROPIC_API_KEY"]

    def test_load_from_yaml(self):
        """Test loading configuration from YAML file."""
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(
                {
                    "anthropic_api_key": "yaml-key-456",
                    "model": {"name": "custom-model", "max_tokens": 6000},
                    "review": {"fail_on_high": True},
                },
                f,
            )
            config_path = f.name

        try:
            config = Config.load(config_path)
            assert config.anthropic_api_key == "yaml-key-456"
            assert config.model.name == "custom-model"
            assert config.model.max_tokens == 6000
            assert config.review.fail_on_high is True
        finally:
            os.unlink(config_path)

    def test_env_overrides_yaml(self):
        """Test environment variable override priority."""
        # Create temporary config file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"anthropic_api_key": "yaml-key-456"}, f)
            config_path = f.name

        try:
            # Set different key in environment
            os.environ["ANTHROPIC_API_KEY"] = "env-key-789"

            config = Config.load(config_path)
            assert config.anthropic_api_key == "env-key-789"

            # Cleanup
            del os.environ["ANTHROPIC_API_KEY"]
        finally:
            os.unlink(config_path)

    def test_validate_api_key_missing(self):
        """Test API key validation fails when missing."""
        config = Config()

        with pytest.raises(ValueError, match="Anthropic API key not configured"):
            config.validate_api_key()

    def test_validate_api_key_present(self):
        """Test API key validation succeeds when present."""
        config = Config(anthropic_api_key="test-key")
        config.validate_api_key()  # Should not raise

    def test_prompt_dir_exists(self):
        """Test prompt directory path resolution."""
        config = Config()
        assert config.prompt_dir.exists()
        assert (config.prompt_dir / "security.md").exists()
