# Transport Modes: stdio vs HTTP

## Current Implementation: stdio (for MCP clients like Cursor)

The LinkedIn MCP server currently uses **stdio transport** which is compatible with:
- Cursor (MCP integration)
- Claude Desktop
- Other MCP clients that communicate via stdin/stdout

### Authentication Flow (stdio)
1. Call `authenticate()` tool
2. Browser opens to LinkedIn
3. User authorizes
4. Callback received on localhost:3000
5. Tokens saved to disk
6. Call `create_post()` tool

### Why Not OAuth Proxy?

FastMCP's OAuth Proxy requires **HTTP transport** to handle:
- OAuth callbacks (GET /auth/callback)
- Dynamic Client Registration endpoints
- Token exchange endpoints

MCP clients like Cursor communicate via **stdio** (standard input/output), not HTTP requests, so they cannot:
- Receive HTTP callbacks from LinkedIn
- Make HTTP requests to OAuth endpoints
- Use the Dynamic Client Registration flow

## Alternative: HTTP Transport (for OAuth Proxy)

If you want to use OAuth Proxy, you need to run the server in HTTP mode and connect to it via HTTP, not stdio.

### Setup for HTTP + OAuth Proxy

1. Create `server_http.py`:
```python
"""HTTP server with OAuth Proxy for web-based MCP clients."""
import os
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth import OAuthProxy
from linkedin_mcp.linkedin.token_verifier import LinkedInTokenVerifier
from linkedin_mcp.config.settings import settings
from linkedin_mcp.linkedin.auth import LinkedInOAuth
from linkedin_mcp.linkedin.post import PostManager

load_dotenv()

PORT = int(os.getenv("PORT", "8000"))
SERVER_BASE_URL = os.getenv("SERVER_BASE_URL", f"http://localhost:{PORT}").rstrip('/')

# Create OAuth Proxy
token_verifier = LinkedInTokenVerifier(required_scopes=settings.LINKEDIN_SCOPES)

auth = OAuthProxy(
    upstream_authorization_endpoint=str(settings.LINKEDIN_AUTH_URL),
    upstream_token_endpoint=str(settings.LINKEDIN_TOKEN_URL),
    upstream_client_id=settings.LINKEDIN_CLIENT_ID.get_secret_value(),
    upstream_client_secret=settings.LINKEDIN_CLIENT_SECRET.get_secret_value(),
    token_verifier=token_verifier,
    base_url=SERVER_BASE_URL,
    redirect_path="/auth/callback",
    forward_pkce=True,
    token_endpoint_auth_method="client_secret_post",
    extra_authorize_params={"scope": " ".join(settings.LINKEDIN_SCOPES)},
    jwt_signing_key=os.getenv("JWT_SIGNING_KEY"),
    require_authorization_consent=False
)

# Create MCP server with OAuth
mcp = FastMCP("LinkedInServer", auth=auth)

# Initialize clients
auth_client = LinkedInOAuth()
post_manager = PostManager(auth_client)

# Add tools...
@mcp.tool()
async def create_post(text: str) -> str:
    # Implementation using OAuth tokens
    pass

if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=PORT)
```

2. Run: `python server_http.py`

3. Access at: `http://localhost:8000`

4. Connect MCP clients via HTTP endpoint, not stdio

### MCP Client Configuration (HTTP)

```json
{
  "mcpServers": {
    "linkedin": {
      "url": "http://localhost:8000/mcp",
      "transport": "http"
    }
  }
}
```

## Comparison

| Feature | stdio (Current) | HTTP + OAuth Proxy |
|---------|----------------|-------------------|
| **Transport** | stdin/stdout | HTTP |
| **MCP Clients** | Cursor, Claude Desktop | Web-based clients |
| **Authentication** | Manual tool call | Automatic OAuth flow |
| **Callback Server** | Separate (port 3000) | Integrated |
| **Token Refresh** | Manual re-auth | Automatic |
| **Setup Complexity** | Simple | More complex |
| **Production Ready** | Basic | Full featured |

## Recommendation

**For Cursor/Claude Desktop**: Use stdio (current implementation)
- Simple setup
- Works out of the box
- No additional server configuration needed

**For Web Applications**: Use HTTP + OAuth Proxy
- Better security
- Automatic token management
- Production-ready
- Requires HTTP server setup

## Current Status

The server is configured for **stdio transport** to work with Cursor and other desktop MCP clients. The OAuth Proxy implementation is documented but not active in the main server.py file.

If you need OAuth Proxy functionality, see the files:
- `IMPLEMENTATION_SUMMARY.md` - OAuth Proxy implementation details
- `README_OAUTH_PROXY.md` - Full OAuth Proxy documentation
- Create a separate `server_http.py` following the example above
