"""LinkedIn OAuth exception definitions.

Note: OAuth flow is now handled by FastMCP's OAuthProxy.
This module only contains exception definitions for API error handling.
"""


class AuthError(Exception):
    """Raised when authentication fails."""
    pass
