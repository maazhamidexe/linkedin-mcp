# Architecture Comparison

This document shows the before and after architecture of the LinkedIn MCP server.

## Before: OAuth as a Tool

```
┌─────────────────────────────────────────────────────────────┐
│                         User/Client                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 1. Call authenticate() tool
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    MCP Server (stdio)                        │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              authenticate() Tool                       │ │
│  │  - Generate state                                      │ │
│  │  - Build auth URL                                      │ │
│  │  - Open browser                                        │ │
│  │  - Wait for callback                                   │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 2. Open browser
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  Browser → LinkedIn OAuth                    │
│  - User logs in                                              │
│  - User approves permissions                                 │
│  - Redirect to callback                                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 3. Callback with code
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          Callback Server (localhost:3000)                    │
│  - Receive authorization code                                │
│  - Validate state                                            │
│  - Send code back to tool                                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 4. Return code
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              authenticate() Tool (continued)                 │
│  - Exchange code for tokens                                  │
│  - Get user info                                             │
│  - Save tokens to file                                       │
│  - Return success message                                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 5. Now call create_post()
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   create_post() Tool                         │
│  - Check if authenticated                                    │
│  - Load tokens from file                                     │
│  - Call LinkedIn API                                         │
│  - Return result                                             │
└─────────────────────────────────────────────────────────────┘
```

### Issues with this approach:
- ❌ Manual authentication step required
- ❌ Two separate servers (MCP + callback)
- ❌ No automatic token refresh
- ❌ Tokens lost on server restart (unless manually saved)
- ❌ Complex callback handling
- ❌ Not DCR-compliant
- ❌ Poor user experience

---

## After: OAuth Proxy Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Client (e.g., Claude)                 │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 1. Dynamic Client Registration
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          FastMCP Server with OAuth Proxy (:8000)             │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              OAuth Proxy                               │ │
│  │  - Handle DCR requests                                 │ │
│  │  - Return upstream credentials                         │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 2. Client registered
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client                              │
│  - Stores "registered" credentials                           │
│  - Initiates authorization when needed                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 3. Request authorization (create_post)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          FastMCP Server - OAuth Proxy (:8000)                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │         Authorization Handler                          │ │
│  │  - Check if client has valid token                     │ │
│  │  - If no: initiate OAuth flow                          │ │
│  │  - If yes: proceed with request                        │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 4. Redirect to LinkedIn
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Browser → LinkedIn OAuth                        │
│  - User logs in                                              │
│  - User approves permissions                                 │
│  - Redirect to /auth/callback                                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 5. Callback with code
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          FastMCP Server - OAuth Proxy (:8000)                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │            Callback Handler                            │ │
│  │  - Receive authorization code                          │ │
│  │  - Exchange code for LinkedIn tokens                   │ │
│  │  - Encrypt and store LinkedIn tokens                   │ │
│  │  - Generate FastMCP JWT token                          │ │
│  │  - Redirect back to client                             │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 6. Return JWT token to client
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client                              │
│  - Stores JWT token                                          │
│  - Retries original request (create_post)                    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 7. create_post with JWT token
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          FastMCP Server - create_post Tool                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           Tool Handler                                 │ │
│  │  - Extract FastMCP JWT from request                    │ │
│  │  - Validate JWT signature                              │ │
│  │  - Load LinkedIn token using JTI                       │ │
│  │  - Decrypt LinkedIn token                              │ │
│  │  - Call LinkedIn API with token                        │ │
│  │  - Return result                                       │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 8. LinkedIn API call
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    LinkedIn API                              │
│  - Validate LinkedIn token                                   │
│  - Create post                                               │
│  - Return post ID                                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │ 9. Success response
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      MCP Client                              │
│  - Displays: "Post created successfully!"                    │
└─────────────────────────────────────────────────────────────┘
```

### Benefits of this approach:
- ✅ Automatic authentication (no manual tool call)
- ✅ Single server handling everything
- ✅ Automatic token refresh
- ✅ Persistent encrypted token storage
- ✅ DCR-compliant (works with all MCP clients)
- ✅ PKCE security at both layers
- ✅ Seamless user experience
- ✅ Production-ready

---

## Token Flow Detail

### Before: Direct Token Storage
```
LinkedIn OAuth → access_token → Save to file → Load from file → Use directly
                                     │
                                     ▼
                           tokens/{user_id}.json
                            (plaintext)
```

### After: Token Factory Pattern
```
LinkedIn OAuth → upstream_token
                      │
                      ├─ Encrypt with Fernet
                      │
                      ├─ Store encrypted: {JTI: encrypted_token}
                      │       │
                      │       ▼
                      │  oauth_tokens/ (encrypted)
                      │
                      └─ Generate FastMCP JWT
                              │
                              ├─ Claims: {iss, aud, client_id, scopes, exp, jti}
                              ├─ Signed with HS256
                              │
                              ▼
                         Return to client
                              │
                              ▼
                         Client uses JWT
                              │
                              ▼
                         Server validates JWT
                              │
                              ├─ Verify signature
                              ├─ Check expiration
                              ├─ Validate audience
                              │
                              ▼
                         Lookup upstream token by JTI
                              │
                              ├─ Decrypt with Fernet
                              │
                              ▼
                         Use LinkedIn token for API call
```

---

## Component Comparison

| Component | Before | After |
|-----------|--------|-------|
| **MCP Server** | Standard MCP server | FastMCP with OAuth Proxy |
| **Authentication** | Manual tool | Automatic OAuth flow |
| **Callback Handler** | Separate server (:3000) | Integrated (:8000/auth/callback) |
| **Token Storage** | File (plaintext) | Encrypted disk/memory store |
| **Token Type** | LinkedIn access token | FastMCP JWT → LinkedIn token |
| **Token Refresh** | Manual | Automatic |
| **Client Registration** | Not supported | DCR-compliant |
| **Security** | Basic | PKCE + Encryption + JWT |
| **Production Ready** | Limited | Full support |

---

## User Experience Comparison

### Before
1. Start MCP client
2. **Call `authenticate()` tool** ← Extra step
3. Browser opens → LinkedIn
4. Approve permissions
5. Wait for callback
6. **Tool returns success** ← Must wait
7. Now can call `create_post()`

Total steps: 7 (with 2 manual actions)

### After
1. Start MCP client
2. Call `create_post()` directly
3. **If not authenticated:** Browser opens → LinkedIn (automatic)
4. Approve permissions (one time only)
5. Post created!

**Subsequent calls:**
1. Call `create_post()`
2. Post created! (no re-authentication)

Total steps: 2-5 (depending on auth status, mostly automatic)

---

## Code Comparison

### Before: Manual Authentication
```python
# Step 1: User must authenticate first
result = await authenticate()
# Returns: "Successfully authenticated with LinkedIn as John Doe!"

# Step 2: Now can create post
result = await create_post(text="Hello LinkedIn!")
# Returns: "Successfully created LinkedIn post with ID: 12345"
```

### After: Automatic Authentication
```python
# Just create the post - authentication happens automatically!
result = await create_post(text="Hello LinkedIn!")
# Returns: "Successfully created LinkedIn post with ID: 12345"
# (Browser opened for auth if needed, then post created automatically)
```

---

## Deployment Comparison

### Before: Development
```bash
# Terminal 1: Run MCP server
python -m linkedin_mcp

# Terminal 2: Callback server auto-starts on :3000
# (or manually manage it)
```

### After: Development
```bash
# Single terminal: Run server
python -m linkedin_mcp
# Everything runs on :8000
```

### Before: Production
```yaml
# Complex deployment
services:
  mcp-server:
    # MCP server
  callback-server:
    # Separate callback server on :3000
  # Manual token management
  # No automatic refresh
```

### After: Production
```yaml
# Simple deployment
services:
  linkedin-mcp:
    image: linkedin-mcp:latest
    environment:
      - LINKEDIN_CLIENT_ID=${CLIENT_ID}
      - LINKEDIN_CLIENT_SECRET=${CLIENT_SECRET}
      - SERVER_BASE_URL=https://api.example.com
      - JWT_SIGNING_KEY=${JWT_KEY}
      - TOKEN_ENCRYPTION_KEY=${ENCRYPTION_KEY}
    volumes:
      - token-storage:/app/linkedin_mcp/oauth_tokens
# Automatic token refresh
# Persistent encrypted storage
# Single service
```

---

## Summary

The OAuth Proxy pattern provides:
- **Better UX**: Automatic authentication, no manual steps
- **Simpler Architecture**: One server instead of two
- **More Secure**: PKCE, encryption, JWT tokens
- **Production Ready**: Persistent storage, auto-refresh, multi-instance support
- **Standard Compliant**: DCR-compatible, works with all MCP clients

The implementation follows FastMCP's best practices and matches the pattern used in production OAuth proxy deployments like the Zoho People MCP server.
