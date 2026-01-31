"""
Kintsugi Configuration Schema.

Defines the structure for .github/kintsugi.yml configuration files.
Users can customize bot behavior, security restrictions, and AI preferences.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class BranchConfig(BaseModel):
    """Branch filtering configuration."""
    allow: List[str] = Field(default=["main", "master", "develop", "feature/*", "kintsugi-fix*"])
    ignore: List[str] = Field(default=["dependabot/**"])


class LimitsConfig(BaseModel):
    """Safety limits to prevent runaway costs and changes."""
    max_attempts: int = Field(default=3, ge=1, le=5)  # Cap at 5 to save API costs
    max_files_changed: int = Field(default=2, ge=1)


class SecurityConfig(BaseModel):
    """Security restrictions - files the bot cannot modify."""
    protected_paths: List[str] = Field(
        default=[
            ".github/**",
            "requirements.txt",
            "package.json",
            "package-lock.json",
            "Dockerfile",
            "docker-compose.yml",
            "*.lock",
        ]
    )
    # Security scanning for LLM-generated code
    scan_enabled: bool = Field(default=True, description="Enable Semgrep security scanning")
    block_on_critical: bool = Field(default=True, description="Block commits with critical security issues")


class AIConfig(BaseModel):
    """AI behavior configuration."""
    mode: str = Field(default="fast")  # smart=Pro, fast=Flash
    extra_instructions: Optional[str] = None


class TestConfig(BaseModel):
    """Test runner configuration."""
    command: Optional[str] = None  # e.g., "npx playwright test {test_file}"


class KintsugiConfig(BaseModel):
    """
    Root configuration object for Kintsugi.
    
    Example .github/kintsugi.yml:
    ```yaml
    version: 1
    demo_password: "your-password-here"  # Required during hackathon demo period
    branches:
      allow: ["main", "develop"]
      ignore: ["dependabot/**"]
    limits:
      max_attempts: 3
      max_files_changed: 2
    security:
      protected_paths:
        - ".github/**"
        - "package.json"
    ai:
      mode: "smart"
      extra_instructions: "Prefer data-testid attributes"
    ```
    """
    version: int = 1
    demo_password: Optional[str] = Field(
        default=None,
        description="Required for activating the app during the hackathon demo period."
    )
    branches: BranchConfig = Field(default_factory=BranchConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    testing: TestConfig = Field(default_factory=TestConfig)
