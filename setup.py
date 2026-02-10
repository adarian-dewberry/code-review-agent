"""
Setup configuration for code-review-agent package.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme = Path(__file__).parent / "README.md"
long_description = readme.read_text() if readme.exists() else ""

setup(
    name="code-review-agent",
    version="0.1.0",
    author="Adarian Dewberry",
    author_email="hello@adariandewberry.ai",
    description="Automated code review agent for AI-powered development",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/adarian-dewberry/code-review-agent",
    packages=find_packages(),
    include_package_data=True,
    package_data={"code_review_agent": ["prompts/*.md"]},
    install_requires=[
        "anthropic>=0.40.0",
        "pyyaml>=6.0",
        "pydantic>=2.0.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.3.0",
            "pytest-cov>=5.0.0",
            "black>=24.8.0",
            "flake8>=7.1.0",
            "mypy>=1.13.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "frankie=code_review_agent.cli:main",
            "code-review=code_review_agent.cli:main",
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
)
