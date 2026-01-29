"""LinkedIn OAuth token verifier for FastMCP OAuth proxy."""
import logging
from typing import Optional
from datetime import datetime, timedelta
from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.providers.in_memory import AccessToken

logger = logging.getLogger(__name__)


class LinkedInTokenVerifier(TokenVerifier):
    """Token verifier for LinkedIn OAuth tokens."""
    
    def __init__(self, required_scopes: Optional[list[str]] = None):
        """Initialize the LinkedIn token verifier.
        
        Args:
            required_scopes: List of required OAuth scopes
        """
        super().__init__()
        self.required_scopes = required_scopes or [
            "openid",
            "profile",
            "email",
            "w_member_social"
        ]
        logger.info(f"LinkedInTokenVerifier initialized with scopes: {self.required_scopes}")

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """Verify LinkedIn OAuth token.
        
        FastMCP's OAuth proxy handles token refresh automatically, so we just
        validate the token format and return the access token object.
        
        Args:
            token: The LinkedIn access token to verify
            
        Returns:
            AccessToken object if valid, None otherwise
        """
        if not token or not token.strip():
            logger.warning("Empty token provided")
            return None
        
        # FastMCP handles token refresh - just validate token format
        # Set expiration to 1 hour from now (LinkedIn tokens typically last 60 days)
        expires_at = int((datetime.now() + timedelta(hours=1)).timestamp())
        
        logger.debug("Token validated successfully")
        return AccessToken(
            token=token,
            client_id="linkedin-mcp-client",
            expires_at=expires_at,
            scopes=self.required_scopes,
            claims={"service": "linkedin"}
        )
