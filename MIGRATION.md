# Migration Guide: OAuth Tool → OAuth Proxy

This document explains the changes made to convert the LinkedIn MCP server from using OAuth as a tool to using FastMCP's OAuth Proxy pattern.

## Summary of Changes

### What Changed

**Before (OAuth as Tool):**
- Users had to manually call an `authenticate()` tool
- Required a local callback server running on port 3000
- Manual token management and storage
- Users needed to authenticate each session

**After (OAuth Proxy):**
- Authentication happens automatically through OAuth flow
- No separate callback server needed - handled by FastMCP
- Automatic token management with refresh
- Persistent token storage (with proper configuration)
- MCP clients register dynamically (DCR-compliant)

## File Changes

### 1. New Files Created

#### `linkedin_mcp/linkedin/token_verifier.py`
- Custom token verifier for LinkedIn OAuth tokens
- Validates tokens and returns AccessToken objects
- Used by the OAuth proxy for token validation

### 2. Modified Files

#### `linkedin_mcp/server.py`
**Key Changes:**
- Removed `authenticate()` tool - authentication now handled by OAuth proxy
- Added OAuth proxy initialization with LinkedIn endpoints
- Added `extract_linkedin_token()` function to get tokens from OAuth context
- Updated `create_post()` to extract and use tokens from OAuth proxy
- Added server startup information and OAuth flow documentation
- Changed from `mcp.server.fastmcp` to `fastmcp` (using FastMCP directly)

#### `linkedin_mcp/config/settings.py`
**Key Changes:**
- Made environment variables more flexible with defaults
- Added OAuth proxy-specific settings:
  - `JWT_SIGNING_KEY` - for signing FastMCP tokens
  - `TOKEN_ENCRYPTION_KEY` - for encrypting stored tokens
  - `OAUTH_TOKEN_STORAGE_PATH` - persistent storage location
- Added `SERVER_BASE_URL` for OAuth callbacks
- Improved validation and error messages

#### `pyproject.toml`
**Key Changes:**
- Updated version from `0.1.7` to `0.2.0`
- Replaced `mcp[cli]` with `fastmcp>=2.12.0`
- Added new dependencies:
  - `cryptography>=44.0.0` - for token encryption
  - `key-value-store>=0.1.0` - for persistent storage
- Removed `python-jose[cryptography]` (not needed with OAuth proxy)

### 3. New Configuration Files

#### `.env.example`
Comprehensive example showing all configuration options:
- LinkedIn OAuth credentials
- Server configuration
- OAuth proxy keys (optional, for production)
- Detailed setup instructions

#### `README_OAUTH_PROXY.md`
Complete documentation covering:
- OAuth proxy architecture explanation
- Setup instructions
- Production deployment guide
- Security features
- Troubleshooting

## Environment Variables

### Required (Minimum Configuration)

```env
LINKEDIN_CLIENT_ID=your_client_id
LINKEDIN_CLIENT_SECRET=your_client_secret
```

### Recommended for Development

```env
LINKEDIN_CLIENT_ID=your_client_id
LINKEDIN_CLIENT_SECRET=your_client_secret
PORT=8000
SERVER_BASE_URL=http://localhost:8000
LINKEDIN_REDIRECT_URI=http://localhost:8000/auth/callback
LOG_LEVEL=INFO
```

### Required for Production

```env
# LinkedIn credentials
LINKEDIN_CLIENT_ID=your_client_id
LINKEDIN_CLIENT_SECRET=your_client_secret

# Production URLs
SERVER_BASE_URL=https://your-domain.com
LINKEDIN_REDIRECT_URI=https://your-domain.com/auth/callback

# Security keys (REQUIRED for persistent tokens)
JWT_SIGNING_KEY=generated_jwt_key
TOKEN_ENCRYPTION_KEY=generated_fernet_key

# Persistent storage
TOKEN_STORAGE_DIR=/mnt/persistent/linkedin-tokens

# Logging
LOG_LEVEL=INFO
```

## LinkedIn App Configuration

### Before
- Redirect URI: `http://localhost:3000/callback`

### After
- Redirect URI: `http://localhost:8000/auth/callback` (development)
- Redirect URI: `https://your-domain.com/auth/callback` (production)

**Important:** Update your LinkedIn app's redirect URI to match the new OAuth proxy callback path!

## User Experience Changes

### Before (OAuth Tool)
1. User starts MCP client
2. User calls `authenticate()` tool
3. Browser opens to LinkedIn
4. User authorizes
5. Local callback server receives code
6. Tool exchanges code for tokens
7. Tokens saved locally
8. User can now call `create_post()`

### After (OAuth Proxy)
1. User starts MCP client
2. Client automatically registers with server (DCR)
3. Client calls `create_post()` tool
4. **If not authenticated:**
   - Server initiates OAuth flow automatically
   - User is redirected to LinkedIn
   - User authorizes
   - Server receives tokens and stores them
   - Request continues
5. **If authenticated:**
   - Request proceeds with existing tokens
   - Tokens auto-refresh if expired

## API Changes

### Removed
- `authenticate()` tool - no longer needed

### Modified
- `create_post()` tool now handles authentication automatically

### Authentication Flow
- Managed entirely by FastMCP OAuth Proxy
- Transparent to end users
- Tokens automatically refreshed when expired

## Deployment Changes

### Development
**Before:**
```bash
python -m linkedin_mcp
# Callback server runs on :3000
# MCP server runs on default MCP port
```

**After:**
```bash
python -m linkedin_mcp
# Single server on :8000
# Handles both MCP and OAuth callbacks
```

### Production
**Before:**
- Required managing two servers
- Manual token persistence
- No automatic refresh

**After:**
- Single server deployment
- Built-in token persistence
- Automatic token refresh
- Supports multiple instances with shared storage

## Security Improvements

1. **PKCE Support** - Now uses PKCE at both client-to-proxy and proxy-to-provider layers
2. **Token Encryption** - Tokens stored encrypted using Fernet (AES-128-CBC + HMAC-SHA256)
3. **JWT Token Factory** - Server issues its own signed tokens maintaining proper audience boundaries
4. **Automatic Refresh** - No need to re-authenticate when tokens expire

## Breaking Changes

⚠️ **Important:** This is a breaking change for existing users.

### For End Users
- **No action required** - OAuth flow now happens automatically
- Remove any scripts calling the old `authenticate()` tool
- Update MCP client configuration if hardcoded to old callback URL

### For Developers
- Update imports: `from mcp.server.fastmcp import FastMCP` → `from fastmcp import FastMCP`
- Install new dependencies: `pip install -e .`
- Update `.env` file with new variables
- Update LinkedIn app redirect URI

## Migration Steps

1. **Backup** your current `.env` file and tokens directory
2. **Update dependencies:**
   ```bash
   pip install -e .
   ```
3. **Update `.env` file:**
   - Add `SERVER_BASE_URL` and `LINKEDIN_REDIRECT_URI`
   - Optionally add `JWT_SIGNING_KEY` and `TOKEN_ENCRYPTION_KEY` for persistence
4. **Update LinkedIn app settings:**
   - Change redirect URI from `:3000/callback` to `:8000/auth/callback`
5. **Test the new flow:**
   ```bash
   python -m linkedin_mcp
   ```
6. **Update client configurations** if needed

## Rollback

If you need to rollback:
```bash
git checkout <previous-commit>
pip install -e .
```

And restore your LinkedIn app's original redirect URI.

## Questions?

- Check [README_OAUTH_PROXY.md](./README_OAUTH_PROXY.md) for detailed documentation
- Review the [FastMCP OAuth Proxy docs](https://fastmcp.dev/docs/authentication/oauth-proxy)
- Open an issue on GitHub for support

---

**Note:** The old `authenticate()` tool approach is still valid for local development or testing, but the OAuth Proxy pattern is recommended for all deployments as it provides better security, automatic token management, and a seamless user experience.
