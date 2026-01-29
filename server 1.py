"""
Zoho People MCP Server with OAuth Proxy
Uses FastMCP's OAuth Proxy for authorization code grant flow
QuickSight registers dynamically and MCP server handles OAuth flow with Zoho
"""
import json
import os
import sys
import logging
import threading
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timedelta
import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP, Context
from fastmcp.server.auth import OAuthProxy, TokenVerifier
from fastmcp.server.auth.providers.in_memory import AccessToken
from fastmcp.server.openapi import RouteMap, MCPType
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_access_token, get_http_request

# Load secrets from AWS Secrets Manager (production) or .env file (development)
try:
    from zoho_people_mcp.secrets_manager import load_secrets_from_aws
    # Try AWS Secrets Manager first (for EC2 deployment)
    secrets = load_secrets_from_aws()
    if not secrets:
        # Fallback to .env file for local development
        load_dotenv()
except ImportError:
    # boto3 not available, use .env file
    load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

# Zoho OAuth Configuration
ZOHO_CLIENT_ID = os.getenv("ZOHO_CLIENT_ID", "")
ZOHO_CLIENT_SECRET = os.getenv("ZOHO_CLIENT_SECRET", "")
ZOHO_AUTH_URL = "https://accounts.zoho.com/oauth/v2/auth"
ZOHO_TOKEN_URL = "https://accounts.zoho.com/oauth/v2/token"

# Required Zoho scopes for QuickSight
REQUIRED_ZOHO_SCOPES = [
    "ZohoPeople.leave.ALL",
    "ZohoPeople.forms.ALL",
    "ZohoPeople.attendance.ALL",
    "ZohoAssist.userapi.READ",
    "ZohoMail.accounts.READ",
    "AaaServer.profile.READ",
    "ZohoPeople.employee.ALL",
    "ZohoPeople.timetracker.ALL",
    "ZohoPeople.training.ALL",
]

# Server configuration
PORT = int(os.getenv("PORT", "8000"))

# Get server base URL (for OAuth callback)
SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", f"http://localhost:{PORT}").rstrip('/')
logger.info(f"Server base URL: {SERVER_BASE_URL}")

# Lambda endpoint
LAMBDA_BASE_URL = "https://dlkyrrvc7zpg6pwx46u4f4q66u0edofl.lambda-url.us-east-1.on.aws"

# Token storage configuration (for persistent tokens)
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY")
TOKEN_ENCRYPTION_KEY = os.getenv("TOKEN_ENCRYPTION_KEY")

# Try to set up persistent storage for AWS container with persistent volume
storage_backend = None
if JWT_SIGNING_KEY and TOKEN_ENCRYPTION_KEY:
    try:
        from key_value.aio.stores.disk import DiskStore
        from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
        from cryptography.fernet import Fernet
        
        # AWS container persistent volume paths (in order of preference)
        storage_candidates = [
            "/mnt/zoho-tokens",  # EBS volume mount point (EC2 persistent storage)
            "/mnt/persistent/zoho-tokens",  # AWS ECS/EKS persistent volume mount point
            "/mnt/data/zoho-tokens",        # Alternative AWS mount point
            "/persistent/zoho-tokens",      # Common persistent volume path
            "/var/lib/zoho-tokens",         # Standard Linux persistent path
        ]
        
        # Allow override via environment variable
        custom_storage_path = os.getenv("TOKEN_STORAGE_DIR")
        if custom_storage_path:
            storage_candidates.insert(0, custom_storage_path)
        
        token_storage_dir = None
        for candidate_dir in storage_candidates:
            try:
                os.makedirs(candidate_dir, exist_ok=True)
                test_file = os.path.join(candidate_dir, ".write_test")
                with open(test_file, 'w') as f:
                    f.write("test")
                os.remove(test_file)
                token_storage_dir = candidate_dir
                logger.info(f"✅ Token storage directory ready: {token_storage_dir}")
                break
            except Exception as e:
                logger.debug(f"Cannot use {candidate_dir}: {e}")
                continue
        
        if not token_storage_dir:
            token_storage_dir = "/tmp/zoho-tokens"
            os.makedirs(token_storage_dir, exist_ok=True)
            logger.warning(f"⚠️  Using ephemeral storage: {token_storage_dir}")
            logger.warning(f"⚠️  All persistent storage paths failed - tokens will be lost on restart!")
            logger.warning(f"⚠️  Set TOKEN_STORAGE_DIR environment variable to a persistent volume path")
        
        storage_backend = FernetEncryptionWrapper(
            key_value=DiskStore(directory=token_storage_dir),
            fernet=Fernet(TOKEN_ENCRYPTION_KEY.encode() if isinstance(TOKEN_ENCRYPTION_KEY, str) else TOKEN_ENCRYPTION_KEY)
        )
        logger.info(f"✅ Configured encrypted token storage at: {token_storage_dir}")
    except Exception as e:
        logger.warning(f"⚠️  Could not configure encrypted storage: {e}")
        storage_backend = None
else:
    logger.warning("⚠️  JWT_SIGNING_KEY or TOKEN_ENCRYPTION_KEY not set - tokens will NOT persist across restarts!")


def load_openapi_spec():
    """Load the OpenAPI specification from the JSON file."""
    spec_path = Path(__file__).parent.parent / "open-api-zoho-v3.json"
    with open(spec_path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_token_from_context(context: Context) -> Optional[str]:
    """
    Extract access token from context.
    FastMCP handles refresh automatically - we only need the access token.
    """
    if context is None:
        logger.warning("Context is None")
        return None

    logger.info(f"Extracting token from context type: {type(context)}")

    # Method 1: Check direct token attributes
    for attr_name in ['token', 'access_token', 'bearer_token', 'oauth_token']:
        if hasattr(context, attr_name):
            token_obj = getattr(context, attr_name)
            if token_obj:
                logger.info(f"Found token in context.{attr_name}")
                if hasattr(token_obj, 'token'):
                    return token_obj.token
                if isinstance(token_obj, str):
                    return token_obj
    
    # Method 2: Check HTTP request headers
    try:
        if hasattr(context, 'get_http_request'):
            http_req = context.get_http_request()
            if http_req and hasattr(http_req, 'headers'):
                headers = http_req.headers
                for header_name in ['Authorization', 'authorization']:
                    auth_header = headers.get(header_name, '')
                    if auth_header and auth_header.startswith('Bearer '):
                        token = auth_header[7:].strip()
                        logger.info(f"Extracted bearer token from header")
                        return token
    except Exception as e:
        logger.warning(f"Error checking HTTP request: {e}")
    
    logger.warning("No token found in context")
    return None


class ZohoTokenVerifier(TokenVerifier):
    """Token verifier for Zoho OAuth tokens."""
    def __init__(self):
        super().__init__()
        logger.info("ZohoTokenVerifier initialized")

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        if not token or not token.strip():
            return None
        
        # FastMCP handles token refresh - just validate token format
        expires_at = int((datetime.now() + timedelta(hours=1)).timestamp())
        
        return AccessToken(
            token=token,
            client_id="zoho-mcp-client",
            expires_at=expires_at,
            scopes=REQUIRED_ZOHO_SCOPES,
            claims={"service": "zoho-people"}
        )


class ThreadSafeLambdaClient:
    """
    Thread-safe HTTP client for forwarding requests to Lambda.
    Uses thread-local storage to isolate tokens between concurrent requests.
    """
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self._local = threading.local()
        logger.info(f"ThreadSafeLambdaClient initialized with base_url: {self.base_url}")

    def set_token(self, token: str):
        """Set the access token for the current thread"""
        self._local.access_token = token

    @property
    def access_token(self) -> Optional[str]:
        """Get the access token for the current thread"""
        return getattr(self._local, 'access_token', None)

    async def forward_request(self, method: str, path: str, params: Optional[dict] = None, data: Optional[dict] = None) -> Any:
        """Forward a request to Lambda with authentication"""
        if not self.access_token:
            raise RuntimeError("No access token available. Please authenticate first.")
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        url = f"{self.base_url}{path}"
        
        async with httpx.AsyncClient() as client:
            if method.upper() == "GET":
                resp = await client.get(url, headers=headers, params=params, timeout=30)
            elif method.upper() == "POST":
                resp = await client.post(url, headers=headers, json=data, params=params, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            if resp.status_code == 401:
                raise RuntimeError("Authentication failed. Token may be expired - FastMCP will refresh automatically on retry.")
            
            resp.raise_for_status()
            return resp.json()


def customize_components(route: Any, component: Any) -> None:
    """Customize MCP components after creation."""
    component.tags.add("zoho-people")
    
    component_type_name = type(component).__name__
    
    if "Tool" in component_type_name:
        component.description = f"🔧 {component.description}"
        component.tags.add("action")
        
        if hasattr(route, "method") and route.method in ["POST", "PUT", "PATCH", "DELETE"]:
            component.tags.add("write-operation")
        else:
            component.tags.add("read-operation")
    
    elif "Resource" in component_type_name and "Template" not in component_type_name:
        component.description = f"📊 {component.description}"
        component.tags.add("data-resource")
    
    elif "ResourceTemplate" in component_type_name:
        component.description = f"🔗 {component.description}"
        component.tags.add("parameterized-resource")
    
    # Add category tags based on route path
    if hasattr(route, "path"):
        path_lower = route.path.lower()
        if "/leave" in path_lower:
            component.tags.add("leave-management")
        elif "/attendance" in path_lower:
            component.tags.add("attendance")
        elif "/timesheet" in path_lower or "/timelog" in path_lower:
            component.tags.add("time-tracking")
        elif "/course" in path_lower or "/training" in path_lower:
            component.tags.add("training")
        elif "/expense" in path_lower or "/travel" in path_lower:
            component.tags.add("expenses")
        elif "/holiday" in path_lower:
            component.tags.add("holidays")


def create_route_maps():
    """Create custom route mappings to convert all endpoints to Tools."""
    return [
        RouteMap(methods=["GET"], pattern=r".*", mcp_type=MCPType.TOOL, mcp_tags={"read-operation", "api-tool"}),
        RouteMap(methods=["POST"], pattern=r".*", mcp_type=MCPType.TOOL, mcp_tags={"write-operation", "api-tool"}),
        RouteMap(methods=["PUT"], pattern=r".*", mcp_type=MCPType.TOOL, mcp_tags={"write-operation", "api-tool"}),
        RouteMap(methods=["PATCH"], pattern=r".*", mcp_type=MCPType.TOOL, mcp_tags={"write-operation", "api-tool"}),
        RouteMap(methods=["DELETE"], pattern=r".*", mcp_type=MCPType.TOOL, mcp_tags={"write-operation", "api-tool"}),
    ]


def create_mcp_server():
    """
    Create and configure the MCP server with OAuth Proxy.
    
    Flow:
    1. QuickSight registers dynamically with MCP server (DCR)
    2. QuickSight requests authorization from MCP server
    3. MCP server (OAuth Proxy) redirects to Zoho with correct scopes
    4. User authorizes with Zoho
    5. Zoho redirects back to MCP server
    6. MCP server exchanges code for Zoho tokens
    7. MCP server issues tokens to QuickSight
    8. QuickSight uses tokens for requests
    9. MCP server forwards requests to Lambda with Zoho tokens
    """
    # Validate configuration
    if not all([ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET]):
        logger.error("Missing required configuration!")
        logger.error("Please set: ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET")
        sys.exit(1)
    
    # Load OpenAPI spec
    openapi_spec = load_openapi_spec()
    
    # Create token verifier
    token_verifier = ZohoTokenVerifier()
    
    # Create OAuth Proxy
    logger.info(f"Creating OAuth Proxy with base_url: {SERVER_BASE_URL}")
    
    auth = OAuthProxy(
        upstream_authorization_endpoint=ZOHO_AUTH_URL,
        upstream_token_endpoint=ZOHO_TOKEN_URL,
        upstream_client_id=ZOHO_CLIENT_ID,
        upstream_client_secret=ZOHO_CLIENT_SECRET,
        token_verifier=token_verifier,
        base_url=SERVER_BASE_URL,
        redirect_path="/oauth/callback",
        forward_pkce=True,
        token_endpoint_auth_method="client_secret_basic",
        allowed_client_redirect_uris=None,
        # Request required Zoho scopes
        extra_authorize_params={
            "scope": " ".join(REQUIRED_ZOHO_SCOPES),
            "access_type": "offline",  # Request refresh token
        },
        jwt_signing_key=JWT_SIGNING_KEY,
        client_storage=storage_backend,
        require_authorization_consent=False
    )
    
    logger.info("✅ OAuth Proxy created successfully")
    logger.info(f"   Authorization endpoint: {ZOHO_AUTH_URL}")
    logger.info(f"   Token endpoint: {ZOHO_TOKEN_URL}")
    logger.info(f"   Redirect path: {SERVER_BASE_URL}/oauth/callback")
    logger.info(f"   Scopes: {', '.join(REQUIRED_ZOHO_SCOPES)}")
    
    # Create Lambda client
    lambda_client = ThreadSafeLambdaClient(LAMBDA_BASE_URL)
    
    # Create custom HTTP client that uses tokens from context
    async def inject_auth_header(request: httpx.Request) -> None:
        """Inject Authorization header using upstream Zoho token from OAuth Proxy"""
        token = None
        
        # Method 1: Get token from thread-local storage (set by middleware - should be upstream token)
        token = lambda_client.access_token
        if token:
            logger.debug("Using token from thread-local storage")
        
        # Method 2: Extract upstream Zoho token from FastMCP JWT token
        if not token:
            try:
                http_request = get_http_request()
                if http_request:
                    auth_header = http_request.headers.get('Authorization') or http_request.headers.get('authorization', '')
                    if auth_header and auth_header.startswith('Bearer '):
                        fastmcp_token = auth_header[7:].strip()
                        # Use OAuth Proxy's load_access_token to swap FastMCP JWT for upstream Zoho token
                        try:
                            upstream_token_obj = await auth.load_access_token(fastmcp_token)
                            if upstream_token_obj and hasattr(upstream_token_obj, 'token'):
                                token = upstream_token_obj.token
                                logger.info("✅ Extracted upstream Zoho token from FastMCP JWT")
                                # Store in thread-local for future use
                                lambda_client.set_token(token)
                            else:
                                logger.warning("load_access_token returned None or invalid token object")
                        except Exception as e:
                            logger.warning(f"Failed to load upstream token from FastMCP JWT: {e}")
                            # Fallback: use FastMCP token directly (Lambda might handle it)
                            token = fastmcp_token
                            logger.debug("Falling back to FastMCP token")
            except Exception as e:
                logger.debug(f"Could not get token from HTTP request: {e}")
        
        # Method 3: Try FastMCP dependency injection
        if not token:
            try:
                access_token_obj = get_access_token()
                if access_token_obj:
                    fastmcp_token = access_token_obj.token if hasattr(access_token_obj, 'token') else access_token_obj
                    if fastmcp_token:
                        # Try to get upstream token
                        try:
                            upstream_token_obj = await auth.load_access_token(fastmcp_token)
                            if upstream_token_obj and hasattr(upstream_token_obj, 'token'):
                                token = upstream_token_obj.token
                                logger.info("✅ Extracted upstream Zoho token via get_access_token()")
                                lambda_client.set_token(token)
                        except Exception:
                            # Fallback to FastMCP token
                            token = fastmcp_token
            except Exception as e:
                logger.debug(f"Could not get token from FastMCP context: {e}")
        
        # Method 4: Fallback to environment variable (should be upstream Zoho token)
        if not token:
            token = os.getenv("ZOHO_OAUTH_TOKEN")
            if token:
                logger.debug("Using token from environment variable")
        
        if not token:
            logger.error("No token found - checking all sources failed")
            raise RuntimeError(
                "Authentication required: No OAuth token provided. "
                "Please authenticate via OAuth flow or set ZOHO_OAUTH_TOKEN environment variable."
            )
        
        request.headers["Authorization"] = f"Bearer {token}"
    
    httpx_client = httpx.AsyncClient(
        base_url=LAMBDA_BASE_URL,
        timeout=30.0,
        event_hooks={"request": [inject_auth_header]}
    )
    
    # Create route maps
    route_maps = create_route_maps()
    
    # Create middleware class to extract tokens from context
    class TokenExtractionMiddleware(Middleware):
        """Middleware to extract upstream Zoho tokens from FastMCP JWT tokens"""
        async def on_request(self, context: MiddlewareContext, call_next) -> Any:
            """Extract upstream Zoho token from FastMCP JWT token"""
            upstream_token = None
            fastmcp_token = None
            
            # Method 1: Try to get FastMCP token from HTTP request headers
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
                except Exception as e:
                    logger.debug(f"Could not get token via get_access_token(): {e}")
            
            # Method 3: Try to extract from FastMCP context
            if not fastmcp_token:
                fastmcp_context = context.fastmcp_context if hasattr(context, 'fastmcp_context') else None
                if fastmcp_context:
                    fastmcp_token = extract_token_from_context(fastmcp_context)
            
            # Swap FastMCP token for upstream Zoho token using OAuth Proxy
            if fastmcp_token:
                try:
                    upstream_token_obj = await auth.load_access_token(fastmcp_token)
                    if upstream_token_obj and hasattr(upstream_token_obj, 'token'):
                        upstream_token = upstream_token_obj.token
                        lambda_client.set_token(upstream_token)
                        logger.info(f"✅ Upstream Zoho token extracted and set for thread {threading.current_thread().ident}")
                    else:
                        logger.warning(f"⚠️  load_access_token returned None or invalid token for thread {threading.current_thread().ident}")
                except Exception as e:
                    logger.warning(f"⚠️  Failed to load upstream token: {e}")
                    # Fallback: store FastMCP token (httpx hook will try to swap it)
                    lambda_client.set_token(fastmcp_token)
                    logger.debug(f"Stored FastMCP token as fallback for thread {threading.current_thread().ident}")
            else:
                logger.warning(f"⚠️  No FastMCP token found for thread {threading.current_thread().ident}")
            
            # Call next middleware/handler in the chain
            return await call_next(context)
    
    # Create FastMCP server
    mcp = FastMCP.from_openapi(
        openapi_spec=openapi_spec,
        client=httpx_client,
        name="Zoho People API",
        tags={"zoho", "people", "hr", "api", "openapi"},
        route_maps=route_maps,
        mcp_component_fn=customize_components,
        auth=auth,  # OAuth Proxy handles all authentication
        middleware=[TokenExtractionMiddleware()]  # Add middleware to extract tokens
    )
    
    logger.info("✅ FastMCP server created with OAuth Proxy")
    
    return mcp


if __name__ == "__main__":
    print("=" * 60)
    print(" Zoho People MCP Server with OAuth Proxy")
    print("=" * 60)
    print(f"   Server URL: {SERVER_BASE_URL}")
    print(f"   OAuth callback: {SERVER_BASE_URL}/oauth/callback")
    print(f"   Lambda endpoint: {LAMBDA_BASE_URL}")
    print("\nIMPORTANT: Your Zoho OAuth app must:")
    print(f"1. Have redirect URI: {SERVER_BASE_URL}/oauth/callback")
    print("2. Support offline_access scope for refresh tokens")
    print("\n📋 OAuth Flow:")
    print("1. QuickSight registers dynamically with MCP server")
    print("2. QuickSight requests authorization")
    print("3. MCP server redirects to Zoho (with correct scopes)")
    print("4. User logs in with Zoho credentials")
    print("5. Zoho returns access + refresh tokens")
    print("6. FastMCP stores tokens persistently")
    print("7. FastMCP automatically refreshes expired tokens")
    print("8. MCP server forwards requests to Lambda with Zoho tokens")
    print("-" * 60)
    
    try:
        mcp = create_mcp_server()
        print(f"\n🚀 Starting server on port {PORT}...")
        print(f"📡 MCP endpoint: {SERVER_BASE_URL}/mcp")
        
        mcp.run(transport="http", host="0.0.0.0", port=PORT)
    except KeyboardInterrupt:
        print("\n👋 Shutting down...")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
