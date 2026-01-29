# Changelog

All notable changes to the LinkedIn MCP server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-21

### 🎉 Major Release: OAuth Proxy Implementation

This release represents a complete architectural shift from manual OAuth tool-based authentication to FastMCP's OAuth Proxy pattern.

### Added
- **OAuth Proxy Integration**: Implemented FastMCP's OAuth Proxy for seamless authentication
- **Automatic Token Management**: Tokens now refresh automatically without user intervention
- **Persistent Token Storage**: Optional encrypted storage for production deployments
- **Security Enhancements**:
  - PKCE (Proof Key for Code Exchange) at both client-to-proxy and proxy-to-provider layers
  - Fernet encryption for stored tokens (AES-128-CBC + HMAC-SHA256)
  - JWT token factory pattern maintaining proper OAuth 2.0 audience boundaries
- **New Token Verifier**: Custom `LinkedInTokenVerifier` class for OAuth token validation
- **Production Features**:
  - Configurable JWT signing keys
  - Configurable token encryption keys
  - Flexible storage backends via `key-value-store`
- **Documentation**:
  - Comprehensive `README_OAUTH_PROXY.md` with full setup guide
  - `MIGRATION.md` with detailed migration instructions
  - `QUICKSTART.md` for rapid setup
  - `IMPLEMENTATION_SUMMARY.md` documenting all changes
  - `.env.example` with detailed configuration examples

### Changed
- **BREAKING**: Replaced manual `authenticate()` tool with automatic OAuth proxy flow
- **BREAKING**: Changed callback URL from `:3000/callback` to `:8000/auth/callback`
- **BREAKING**: Updated from `mcp[cli]` to `fastmcp>=2.12.0`
- **Import Path**: Changed from `mcp.server.fastmcp` to `fastmcp`
- **Server Architecture**: Single server now handles both MCP and OAuth callbacks
- **Token Extraction**: Implemented `extract_linkedin_token()` for OAuth context
- **Settings**: Made environment variables more flexible with sensible defaults
- **Dependencies**: Updated to use FastMCP's built-in OAuth capabilities

### Removed
- **BREAKING**: Removed `authenticate()` tool (replaced by OAuth proxy)
- **BREAKING**: Removed separate callback server (integrated into main server)
- Removed `python-jose[cryptography]` dependency (not needed with FastMCP)

### Fixed
- Token persistence across server restarts (with proper configuration)
- Race conditions in OAuth callback handling
- Token refresh errors

### Dependencies
- Added: `fastmcp>=2.12.0`
- Added: `cryptography>=44.0.0`
- Added: `key-value-store>=0.1.0`
- Removed: `mcp[cli]>=1.2.0`
- Removed: `python-jose[cryptography]>=3.3.0`

### Migration Notes
Users upgrading from v0.1.x must:
1. Update dependencies: `pip install -e .`
2. Update `.env` file with new variables (see `.env.example`)
3. Update LinkedIn app redirect URI to `:8000/auth/callback`
4. Remove any scripts calling the old `authenticate()` tool
5. See [MIGRATION.md](./MIGRATION.md) for detailed instructions

### Security Notes
For production deployments:
- Generate and set `JWT_SIGNING_KEY` environment variable
- Generate and set `TOKEN_ENCRYPTION_KEY` environment variable
- Configure `TOKEN_STORAGE_DIR` to point to persistent storage
- Ensure HTTPS is enabled
- Review security best practices in [README_OAUTH_PROXY.md](./README_OAUTH_PROXY.md)

---

## [0.1.7] - Previous Release

### Features
- Manual OAuth authentication via `authenticate()` tool
- LinkedIn post creation with text and media
- Basic token storage
- Local callback server on port 3000

### Known Issues
- Required manual authentication each session
- No automatic token refresh
- Separate callback server complexity
- Limited production deployment support

---

## Upgrade Guide

### From 0.1.x to 0.2.0

**Step 1: Backup**
```bash
# Backup your current configuration
cp .env .env.backup
cp -r linkedin_mcp/tokens tokens.backup
```

**Step 2: Update**
```bash
# Update dependencies
pip install -e .

# Update .env (see .env.example for new variables)
# Minimum required: LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET
```

**Step 3: Update LinkedIn App**
- Change redirect URI from `:3000/callback` to `:8000/auth/callback`

**Step 4: Test**
```bash
# Run the server
python -m linkedin_mcp

# Test with your MCP client
```

**Step 5: Production (Optional)**
```bash
# Generate keys
python -c "import secrets; print(secrets.token_urlsafe(32))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Add to .env:
# JWT_SIGNING_KEY=<generated_jwt_key>
# TOKEN_ENCRYPTION_KEY=<generated_fernet_key>
```

---

## Future Roadmap

### Planned Features
- LinkedIn profile management tools
- Company page posting
- Post analytics and insights
- Draft post management
- Scheduled posting
- Multi-account support

### Under Consideration
- LinkedIn messaging integration
- Connection management
- Post engagement tracking
- Content recommendations

---

[0.2.0]: https://github.com/your-repo/linkedin-mcp/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/your-repo/linkedin-mcp/releases/tag/v0.1.7
