"""
Application configuration using Pydantic Settings.

Loads environment variables for GitHub App authentication,
webhook validation, and Gemini API access.
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Attributes:
        app_name: Name of the application.
        debug: Enable debug mode.
        github_app_id: GitHub App ID for authentication.
        github_private_key: GitHub App private key (PEM format).
        webhook_secret: Secret for validating GitHub webhook signatures.
        gemini_api_key: API key for Google Gemini 3.
        api_host: Host to bind the API server.
        api_port: Port to bind the API server.
    """
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )
    
    # Application Settings
    app_name: str = Field(default="Kintsugi", description="Application name")
    debug: bool = Field(default=False, description="Enable debug mode")
    
    # GitHub App Configuration
    github_app_id: str = Field(
        ...,
        description="GitHub App ID",
        json_schema_extra={"env": "GITHUB_APP_ID"},
    )
    github_private_key: SecretStr = Field(
        ...,
        description="GitHub App private key in PEM format",
        json_schema_extra={"env": "GITHUB_PRIVATE_KEY"},
    )
    webhook_secret: SecretStr = Field(
        ...,
        description="Secret for validating webhook signatures",
        json_schema_extra={"env": "WEBHOOK_SECRET"},
    )
    
    # Gemini API Configuration
    gemini_api_key: SecretStr = Field(
        ...,
        description="Google Gemini API key",
        json_schema_extra={"env": "GEMINI_API_KEY"},
    )
    
    # Demo/Hackathon Mode - Password protection
    judge_password: SecretStr = Field(
        default=SecretStr(""),
        description="Master password to activate the app during hackathon/demo period",
        json_schema_extra={"env": "JUDGE_PASSWORD"},
    )
    
    # Server Configuration
    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    
    # GitHub API Configuration
    github_api_base_url: str = Field(
        default="https://api.github.com",
        description="GitHub API base URL",
    )
    
    @field_validator("github_private_key", mode="before")
    @classmethod
    def validate_private_key(cls, v: str) -> str:
        """Validate that the private key looks like a PEM key."""
        if v and not v.strip().startswith("-----BEGIN"):
            # Allow for newline-escaped keys from environment
            v = v.replace("\\n", "\n")
        return v


@lru_cache
def get_settings() -> Settings:
    """
    Get cached application settings.
    
    Returns:
        Settings: The application settings instance.
    """
    return Settings()


# Global settings instance for convenience
settings = get_settings()
