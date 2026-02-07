"""Package setup configuration."""

from setuptools import setup, find_packages

setup(
    name="code-review-agent",
    version="0.1.0",
    description="Automated code review using Claude AI",
    author="Code Review Agent Contributors",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "anthropic>=0.7.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "code-review-agent=code_review_agent.cli:main",
        ],
    },
)
