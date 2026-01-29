"""
LinkedIn MCP Server with FastMCP OAuth Proxy
Uses FastMCP's OAuth Proxy for authorization code grant flow
MCP clients register dynamically and server handles OAuth flow with LinkedIn
"""
import logging
import os
import sys
import threading
from typing import List, Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP, Context
from fastmcp.server.auth import OAuthProxy
from fastmcp.server.dependencies import get_access_token, get_http_request
from .linkedin.post import PostCreationError
from .linkedin.token_verifier import LinkedInTokenVerifier
from .utils.logging import configure_logging
from .config.settings import settings

# Load environment variables
load_dotenv()

# Configure logging
configure_logging(log_level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

# Server configuration
PORT = settings.SERVER_PORT
SERVER_BASE_URL = settings.SERVER_BASE_URL
logger.info(f"Server base URL: {SERVER_BASE_URL}")

# LinkedIn API endpoints
LINKEDIN_USERINFO_URL = str(settings.LINKEDIN_USERINFO_URL)
LINKEDIN_POST_URL = str(settings.LINKEDIN_POST_URL)
LINKEDIN_ASSET_REGISTER_URL = str(settings.LINKEDIN_ASSET_REGISTER_URL)

# Token storage configuration
JWT_SIGNING_KEY = settings.JWT_SIGNING_KEY.get_secret_value() if settings.JWT_SIGNING_KEY else None
TOKEN_ENCRYPTION_KEY = settings.TOKEN_ENCRYPTION_KEY.get_secret_value() if settings.TOKEN_ENCRYPTION_KEY else None

# Set up persistent storage for tokens if encryption keys are available
storage_backend = None
if JWT_SIGNING_KEY and TOKEN_ENCRYPTION_KEY:
    try:
        from key_value.aio.stores.disk import DiskStore
        from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
        from cryptography.fernet import Fernet
        
        token_storage_dir = settings.OAUTH_TOKEN_STORAGE_PATH
        os.makedirs(token_storage_dir, exist_ok=True)
        
        storage_backend = FernetEncryptionWrapper(
            key_value=DiskStore(directory=token_storage_dir),
            fernet=Fernet(TOKEN_ENCRYPTION_KEY.encode() if isinstance(TOKEN_ENCRYPTION_KEY, str) else TOKEN_ENCRYPTION_KEY)
        )
        logger.info(f"✅ Configured encrypted token storage at: {token_storage_dir}")
    except ImportError:
        logger.warning("⚠️  key-value or cryptography not installed - tokens will NOT persist across restarts")
        storage_backend = None
    except Exception as e:
        logger.warning(f"⚠️  Could not configure encrypted storage: {e}")
        storage_backend = None
else:
    logger.warning("⚠️  JWT_SIGNING_KEY or TOKEN_ENCRYPTION_KEY not set - tokens will NOT persist across restarts")

# LinkedIn OAuth endpoints
LINKEDIN_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
LINKEDIN_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"

# Create token verifier
token_verifier = LinkedInTokenVerifier(required_scopes=settings.LINKEDIN_SCOPES)

# Create OAuth Proxy for LinkedIn
logger.info(f"Creating OAuth Proxy with base_url: {SERVER_BASE_URL}")

auth = OAuthProxy(
    # LinkedIn OAuth endpoints
    upstream_authorization_endpoint=LINKEDIN_AUTH_URL,
    upstream_token_endpoint=LINKEDIN_TOKEN_URL,
    
    # Your registered LinkedIn app credentials
    upstream_client_id=settings.LINKEDIN_CLIENT_ID.get_secret_value(),
    upstream_client_secret=settings.LINKEDIN_CLIENT_SECRET.get_secret_value(),
    
    # Token verification
    token_verifier=token_verifier,
    
    # Your FastMCP server's public URL
    base_url=SERVER_BASE_URL,
    
    # OAuth callback path (must match LinkedIn app settings)
    redirect_path="/auth/callback",
    
    # LinkedIn requires client_secret_post (credentials in POST body)
    token_endpoint_auth_method="client_secret_post",
    
    # Forward PKCE to LinkedIn (LinkedIn supports PKCE)
    forward_pkce=True,
    
    # Allow any client redirect URI for MCP clients
    allowed_client_redirect_uris=None,
    
    # Add scope to authorization request
    extra_authorize_params={
        "scope": " ".join(settings.LINKEDIN_SCOPES),
    },
    
    # Token storage configuration
    jwt_signing_key=JWT_SIGNING_KEY,
    client_storage=storage_backend,
    
    # Skip consent screen for smoother flow
    require_authorization_consent=False
)

logger.info("✅ OAuth Proxy created successfully")
logger.info(f"   Authorization endpoint: {LINKEDIN_AUTH_URL}")
logger.info(f"   Token endpoint: {LINKEDIN_TOKEN_URL}")
logger.info(f"   Redirect path: {SERVER_BASE_URL}/auth/callback")
logger.info(f"   Scopes: {', '.join(settings.LINKEDIN_SCOPES)}")


class ThreadSafeTokenHolder:
    """
    Thread-safe holder for access tokens.
    Uses thread-local storage to isolate tokens between concurrent requests.
    """
    def __init__(self):
        self._local = threading.local()
        logger.debug("ThreadSafeTokenHolder initialized")

    def set_token(self, token: str):
        """Set the access token for the current thread."""
        self._local.access_token = token

    @property
    def access_token(self) -> Optional[str]:
        """Get the access token for the current thread."""
        return getattr(self._local, 'access_token', None)


# Global token holder for the current request
token_holder = ThreadSafeTokenHolder()


async def extract_linkedin_token() -> Optional[str]:
    """
    Extract the upstream LinkedIn access token from the FastMCP context.
    
    This function handles the token exchange from FastMCP JWT to the actual
    LinkedIn upstream token that can be used for API calls.
    """
    fastmcp_token = None
    
    # Method 1: Try to get token from HTTP request headers
    try:
        http_request = get_http_request()
        if http_request:
            auth_header = http_request.headers.get('Authorization') or http_request.headers.get('authorization', '')
            if auth_header and auth_header.startswith('Bearer '):
                fastmcp_token = auth_header[7:].strip()
                logger.debug(f"Got FastMCP token from HTTP header for thread {threading.current_thread().ident}")
    except Exception as e:
        logger.debug(f"Could not get token from HTTP request: {e}")
    
    # Method 2: Try FastMCP dependency injection
    if not fastmcp_token:
        try:
            access_token_obj = get_access_token()
            if access_token_obj:
                if hasattr(access_token_obj, 'token'):
                    fastmcp_token = access_token_obj.token
                elif isinstance(access_token_obj, str):
                    fastmcp_token = access_token_obj
                logger.debug("Got FastMCP token from get_access_token()")
        except Exception as e:
            logger.debug(f"Could not get token via get_access_token(): {e}")
    
    # Method 3: Check thread-local storage (set by middleware)
    if not fastmcp_token:
        token = token_holder.access_token
        if token:
            logger.debug("Using token from thread-local storage")
            return token
    
    # Swap FastMCP JWT for upstream LinkedIn token using OAuth Proxy
    if fastmcp_token:
        try:
            upstream_token_obj = await auth.load_access_token(fastmcp_token)
            if upstream_token_obj and hasattr(upstream_token_obj, 'token'):
                upstream_token = upstream_token_obj.token
                token_holder.set_token(upstream_token)
                logger.info(f"✅ Extracted upstream LinkedIn token for thread {threading.current_thread().ident}")
                return upstream_token
            else:
                logger.warning("load_access_token returned None or invalid token object")
        except Exception as e:
            logger.warning(f"Failed to load upstream token from FastMCP JWT: {e}")
            # Fallback: use FastMCP token directly
            token_holder.set_token(fastmcp_token)
            return fastmcp_token
    
    logger.warning("No token found in context")
    return None


def get_linkedin_headers(access_token: str) -> dict:
    """Get headers for LinkedIn API requests."""
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Restli-Protocol-Version": settings.RESTLI_PROTOCOL_VERSION,
        "LinkedIn-Version": settings.LINKEDIN_VERSION,
        "Content-Type": "application/json"
    }


# Initialize MCP server with OAuth proxy
mcp = FastMCP("LinkedInServer", auth=auth)


@mcp.tool()
async def get_profile(ctx: Context = None) -> str:
    """Get the authenticated LinkedIn user's profile information.
    
    Returns profile details including name, email, and profile picture URL.
    
    Returns:
        JSON string with user profile information
    """
    logger.info("Getting LinkedIn profile...")
    
    try:
        # Extract LinkedIn token from OAuth proxy
        access_token = await extract_linkedin_token()
        if not access_token:
            raise RuntimeError(
                "Not authenticated. Please complete the OAuth flow first. "
                "Your MCP client should prompt you to authenticate."
            )
        
        # Make request to LinkedIn userinfo endpoint
        async with httpx.AsyncClient() as client:
            response = await client.get(
                LINKEDIN_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if response.status_code == 401:
                raise RuntimeError(
                    "Authentication expired. Please re-authenticate via OAuth flow."
                )
            
            response.raise_for_status()
            user_data = response.json()
            
            logger.info(f"Successfully retrieved profile for: {user_data.get('name', 'unknown')}")
            
            # Return formatted profile information
            return f"""LinkedIn Profile:
- Name: {user_data.get('name', 'N/A')}
- Given Name: {user_data.get('given_name', 'N/A')}
- Family Name: {user_data.get('family_name', 'N/A')}
- Email: {user_data.get('email', 'N/A')}
- Email Verified: {user_data.get('email_verified', 'N/A')}
- User ID (sub): {user_data.get('sub', 'N/A')}
- Picture URL: {user_data.get('picture', 'N/A')}"""
    
    except httpx.HTTPStatusError as e:
        error_msg = f"HTTP error getting profile: {e.response.status_code}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as e:
        error_msg = f"Failed to get profile: {str(e)}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg)


@mcp.tool()
async def create_post(
    text: str,
    visibility: str = "PUBLIC",
    ctx: Context = None
) -> str:
    """Create a new text post on LinkedIn.
    
    This tool creates a simple text post. For posts with media attachments,
    use create_post_with_media instead.

    Args:
        text: The content of your post (required)
        visibility: Post visibility - "PUBLIC" or "CONNECTIONS" (default: PUBLIC)

    Returns:
        Success message with post ID
    """
    logger.info("Creating LinkedIn post...")
    
    try:
        # Extract LinkedIn token from OAuth proxy
        access_token = await extract_linkedin_token()
        if not access_token:
            raise RuntimeError(
                "Not authenticated. Please complete the OAuth flow first. "
                "Your MCP client should prompt you to authenticate."
            )
        
        if not text.strip():
            raise RuntimeError("Post text cannot be empty")
        
        # Validate visibility
        if visibility not in ["PUBLIC", "CONNECTIONS"]:
            raise RuntimeError(f"Invalid visibility: {visibility}. Must be PUBLIC or CONNECTIONS")
        
        # First, get user info to get the user ID
        async with httpx.AsyncClient() as client:
            # Get user ID
            user_response = await client.get(
                LINKEDIN_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code == 401:
                raise RuntimeError("Authentication expired. Please re-authenticate.")
            
            user_response.raise_for_status()
            user_data = user_response.json()
            user_id = user_data.get('sub')
            
            if not user_id:
                raise RuntimeError("Could not get user ID from profile")
            
            logger.info(f"Creating post for user: {user_id}")
            
            # Build post payload
            payload = {
                "author": f"urn:li:person:{user_id}",
                "lifecycleState": "PUBLISHED",
                "specificContent": {
                    "com.linkedin.ugc.ShareContent": {
                        "shareCommentary": {
                            "text": text
                        },
                        "shareMediaCategory": "NONE"
                    }
                },
                "visibility": {
                    "com.linkedin.ugc.MemberNetworkVisibility": visibility
                }
            }
            
            # Create the post
            headers = get_linkedin_headers(access_token)
            response = await client.post(
                LINKEDIN_POST_URL,
                headers=headers,
                json=payload
            )
            
            if response.status_code == 401:
                raise RuntimeError("Authentication expired. Please re-authenticate.")
            
            response.raise_for_status()
            
            post_id = response.headers.get("x-restli-id")
            if not post_id:
                raise RuntimeError("No post ID returned from LinkedIn")
            
            success_msg = f"Successfully created LinkedIn post with ID: {post_id}"
            logger.info(success_msg)
            return success_msg
    
    except httpx.HTTPStatusError as e:
        error_text = e.response.text if hasattr(e.response, 'text') else str(e)
        error_msg = f"HTTP error creating post: {e.response.status_code} - {error_text}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as e:
        error_msg = f"Failed to create post: {str(e)}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg)


@mcp.tool()
async def create_post_with_media(
    text: str,
    media_urls: List[str],
    media_titles: List[str] = None,
    media_descriptions: List[str] = None,
    visibility: str = "PUBLIC",
    ctx: Context = None
) -> str:
    """Create a new LinkedIn post with article/link attachments.
    
    Note: For image/video uploads, LinkedIn requires a multi-step process
    involving asset registration and binary upload. This tool supports
    sharing URLs/articles. For local file uploads, additional implementation
    is needed.

    Args:
        text: The content of your post (required)
        media_urls: List of URLs to share (articles, websites)
        media_titles: Optional titles for the shared URLs
        media_descriptions: Optional descriptions for the shared URLs
        visibility: Post visibility - "PUBLIC" or "CONNECTIONS" (default: PUBLIC)

    Returns:
        Success message with post ID
    """
    logger.info("Creating LinkedIn post with media...")
    
    try:
        # Extract LinkedIn token from OAuth proxy
        access_token = await extract_linkedin_token()
        if not access_token:
            raise RuntimeError(
                "Not authenticated. Please complete the OAuth flow first. "
                "Your MCP client should prompt you to authenticate."
            )
        
        if not text.strip():
            raise RuntimeError("Post text cannot be empty")
        
        if not media_urls:
            raise RuntimeError("At least one media URL is required")
        
        # Validate visibility
        if visibility not in ["PUBLIC", "CONNECTIONS"]:
            raise RuntimeError(f"Invalid visibility: {visibility}. Must be PUBLIC or CONNECTIONS")
        
        async with httpx.AsyncClient() as client:
            # Get user ID
            user_response = await client.get(
                LINKEDIN_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code == 401:
                raise RuntimeError("Authentication expired. Please re-authenticate.")
            
            user_response.raise_for_status()
            user_data = user_response.json()
            user_id = user_data.get('sub')
            
            if not user_id:
                raise RuntimeError("Could not get user ID from profile")
            
            # Build media list
            media_list = []
            for i, url in enumerate(media_urls):
                media_item = {
                    "status": "READY",
                    "originalUrl": url,
                    "title": {
                        "text": media_titles[i] if media_titles and i < len(media_titles) else f"Link {i + 1}"
                    },
                    "description": {
                        "text": media_descriptions[i] if media_descriptions and i < len(media_descriptions) else ""
                    }
                }
                media_list.append(media_item)
            
            # Build post payload
            payload = {
                "author": f"urn:li:person:{user_id}",
                "lifecycleState": "PUBLISHED",
                "specificContent": {
                    "com.linkedin.ugc.ShareContent": {
                        "shareCommentary": {
                            "text": text
                        },
                        "shareMediaCategory": "ARTICLE",
                        "media": media_list
                    }
                },
                "visibility": {
                    "com.linkedin.ugc.MemberNetworkVisibility": visibility
                }
            }
            
            # Create the post
            headers = get_linkedin_headers(access_token)
            response = await client.post(
                LINKEDIN_POST_URL,
                headers=headers,
                json=payload
            )
            
            if response.status_code == 401:
                raise RuntimeError("Authentication expired. Please re-authenticate.")
            
            response.raise_for_status()
            
            post_id = response.headers.get("x-restli-id")
            if not post_id:
                raise RuntimeError("No post ID returned from LinkedIn")
            
            success_msg = f"Successfully created LinkedIn post with media. Post ID: {post_id}"
            logger.info(success_msg)
            return success_msg
    
    except httpx.HTTPStatusError as e:
        error_text = e.response.text if hasattr(e.response, 'text') else str(e)
        error_msg = f"HTTP error creating post: {e.response.status_code} - {error_text}"
        logger.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as e:
        error_msg = f"Failed to create post with media: {str(e)}"
        logger.exception(error_msg)
        raise RuntimeError(error_msg)


def main():
    """Main function for running the LinkedIn MCP server with OAuth Proxy."""
    print("=" * 60)
    print(" LinkedIn MCP Server with OAuth Proxy")
    print("=" * 60)
    print(f"   Server URL: {SERVER_BASE_URL}")
    print(f"   OAuth callback: {SERVER_BASE_URL}/auth/callback")
    print(f"   MCP endpoint: {SERVER_BASE_URL}/mcp")
    print("\n📋 SETUP REQUIREMENTS:")
    print("Your LinkedIn OAuth app (developers.linkedin.com) must have:")
    print(f"  1. Authorized redirect URL: {SERVER_BASE_URL}/auth/callback")
    print(f"  2. Products enabled: Sign In with LinkedIn using OpenID Connect, Share on LinkedIn")
    print(f"  3. Scopes granted: {', '.join(settings.LINKEDIN_SCOPES)}")
    print("\n📋 OAuth Flow (automatic for MCP clients):")
    print("  1. MCP client (Cursor/Claude) registers dynamically with server")
    print("  2. Client requests authorization")
    print("  3. Server redirects to LinkedIn OAuth login page")
    print("  4. User logs in with LinkedIn credentials")
    print("  5. LinkedIn returns authorization code")
    print("  6. Server exchanges code for tokens")
    print("  7. FastMCP stores tokens (refresh handled automatically)")
    print("  8. Client uses tokens to access LinkedIn tools")
    print("\n📡 Connect your MCP client to: " + SERVER_BASE_URL + "/mcp")
    print("-" * 60)
    
    try:
        logger.info(f"\n🚀 Starting HTTP server on port {PORT}...")
        logger.info(f"📡 MCP SSE endpoint: {SERVER_BASE_URL}/sse")
        
        mcp.run(transport="http", host="0.0.0.0", port=PORT)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
