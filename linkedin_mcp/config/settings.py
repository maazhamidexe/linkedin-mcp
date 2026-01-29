"""MCP LinkedIn server configuration."""
import os

from dotenv import load_dotenv
from pydantic import HttpUrl, SecretStr, Field, ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # LinkedIn OAuth Settings
    load_dotenv()
    LINKEDIN_CLIENT_ID: SecretStr = Field(
        default=SecretStr(os.getenv("LINKEDIN_CLIENT_ID", "")),
        description="LinkedIn OAuth Client ID"
    )
    LINKEDIN_CLIENT_SECRET: SecretStr = Field(
        default=SecretStr(os.getenv("LINKEDIN_CLIENT_SECRET", "")),
        description="LinkedIn OAuth Client Secret"
    )
    LINKEDIN_REDIRECT_URI: HttpUrl = Field(
        default=os.getenv("LINKEDIN_REDIRECT_URI", "http://localhost:8000/auth/callback"),
        description="OIDC redirect URI (used by OIDC proxy)"
    )

    # API Endpoints
    LINKEDIN_AUTH_URL: HttpUrl = Field(
        default="https://www.linkedin.com/oauth/v2/authorization",
        description="LinkedIn OAuth authorization endpoint"
    )
    LINKEDIN_TOKEN_URL: HttpUrl = Field(
        default="https://www.linkedin.com/oauth/v2/accessToken",
        description="LinkedIn OAuth token endpoint"
    )
    LINKEDIN_USERINFO_URL: HttpUrl = Field(
        default="https://api.linkedin.com/v2/userinfo",
        description="LinkedIn user info endpoint"
    )
    LINKEDIN_POST_URL: HttpUrl = Field(
        default="https://api.linkedin.com/v2/ugcPosts",
        description="LinkedIn posts endpoint"
    )
    LINKEDIN_ASSET_REGISTER_URL: HttpUrl = Field(
        default="https://api.linkedin.com/v2/assets?action=registerUpload",
        description="LinkedIn asset registration endpoint"
    )

    # OAuth Scopes
    LINKEDIN_SCOPES: list[str] = [
        "openid",  # For authentication
        "profile",  # Basic profile access
        "email",  # Email address access
        "w_member_social"  # Required for posting
    ]

    # API Version Headers
    LINKEDIN_VERSION: str = "202210"  # LinkedIn API version
    RESTLI_PROTOCOL_VERSION: str = "2.0.0"  # Rest.li protocol version

    # Token Storage Settings (for legacy auth - not used with OAuth proxy)
    TOKEN_STORAGE_PATH: str = os.path.join("linkedin_mcp", "tokens")

    # OAuth Proxy Storage Settings
    OAUTH_TOKEN_STORAGE_PATH: str = os.getenv(
        "TOKEN_STORAGE_DIR",
        os.path.join("linkedin_mcp", "oauth_tokens")
    )

    # Logging Configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # Server Configuration
    SERVER_PORT: int = int(os.getenv("PORT", "8000"))
    SERVER_BASE_URL: str = os.getenv(
        "SERVER_BASE_URL",
        f"http://localhost:{int(os.getenv('PORT', '8000'))}"
    ).rstrip('/')

    # OAuth Proxy Keys (for production deployments)
    JWT_SIGNING_KEY: SecretStr | None = Field(
        default=SecretStr(os.getenv("JWT_SIGNING_KEY", "")) if os.getenv("JWT_SIGNING_KEY") else None,
        description="Secret for signing FastMCP JWT tokens"
    )
    TOKEN_ENCRYPTION_KEY: SecretStr | None = Field(
        default=SecretStr(os.getenv("TOKEN_ENCRYPTION_KEY", "")) if os.getenv("TOKEN_ENCRYPTION_KEY") else None,
        description="Fernet key for encrypting stored tokens"
    )

    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=True,
        validate_default=True,
        extra="ignore"  # Ignore extra environment variables
    )

    @property
    def formatted_scopes(self) -> str:
        """Get properly formatted scope string."""
        return " ".join(self.LINKEDIN_SCOPES)


# Initialize settings
settings = Settings()

# Validate required settings
if not settings.LINKEDIN_CLIENT_ID or not settings.LINKEDIN_CLIENT_ID.get_secret_value():
    raise ValueError("LINKEDIN_CLIENT_ID must be set in environment variables or .env file")
if not settings.LINKEDIN_CLIENT_SECRET or not settings.LINKEDIN_CLIENT_SECRET.get_secret_value():
    raise ValueError("LINKEDIN_CLIENT_SECRET must be set in environment variables or .env file")

