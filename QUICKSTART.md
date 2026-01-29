# Quick Start Guide - LinkedIn MCP with OAuth Proxy

Get up and running in 5 minutes!

## Prerequisites
- Python 3.12+
- LinkedIn Developer account
- LinkedIn OAuth app credentials

## Step 1: Install Dependencies (30 seconds)

```bash
cd linkedin-mcp
pip install -e .
```

## Step 2: Configure Environment (2 minutes)

```bash
# Copy the example environment file
cp .env.example .env
```

Edit `.env` and add your LinkedIn credentials:

```env
LINKEDIN_CLIENT_ID=your_client_id_here
LINKEDIN_CLIENT_SECRET=your_client_secret_here
```

That's it! The server will use defaults for everything else.

## Step 3: Update LinkedIn App Settings (1 minute)

1. Go to [LinkedIn Developers](https://www.linkedin.com/developers/apps)
2. Open your app settings
3. Add redirect URI: `http://localhost:8000/auth/callback`
4. Make sure you have these scopes enabled:
   - Sign In with LinkedIn using OpenID Connect
   - Share on LinkedIn

## Step 4: Run the Server (30 seconds)

```bash
python -m linkedin_mcp
```

You should see:

```
============================================================
 LinkedIn MCP Server with OAuth Proxy
============================================================
   Server URL: http://localhost:8000
   OAuth callback: http://localhost:8000/auth/callback

IMPORTANT: Your LinkedIn OAuth app must:
1. Have redirect URI: http://localhost:8000/auth/callback
2. Have scopes: openid, profile, email, w_member_social

📋 OAuth Flow:
1. MCP client registers dynamically with server
2. Client requests authorization
3. Server redirects to LinkedIn (with correct scopes)
4. User logs in with LinkedIn credentials
5. LinkedIn returns access token
6. FastMCP stores tokens persistently
7. FastMCP automatically refreshes expired tokens
8. Client uses tokens to create LinkedIn posts
------------------------------------------------------------

🚀 Starting server on port 8000...
📡 MCP endpoint: http://localhost:8000/mcp
```

## Step 5: Test It! (1 minute)

Connect your MCP client to `http://localhost:8000` and try creating a post:

```python
# The OAuth flow happens automatically!
result = create_post(text="Hello LinkedIn! 🎉")
```

## What Happens Next?

1. **First time:** Your browser opens to LinkedIn for authorization
2. **You approve** the permissions
3. **Tokens are stored** automatically
4. **Your post is created!**
5. **Future requests:** No re-authentication needed (tokens refresh automatically)

## Troubleshooting

### Can't find credentials?
- Make sure `.env` file exists in the project root
- Check that `LINKEDIN_CLIENT_ID` and `LINKEDIN_CLIENT_SECRET` are set

### Redirect URI mismatch?
- Verify LinkedIn app settings match: `http://localhost:8000/auth/callback`
- Make sure there are no typos or extra characters

### Port already in use?
```bash
# Use a different port
PORT=8080 python -m linkedin_mcp
# Don't forget to update LinkedIn app redirect URI to :8080!
```

## Optional: Production Setup

For production deployments, generate security keys:

```bash
# Generate JWT signing key
python -c "import secrets; print('JWT_SIGNING_KEY=' + secrets.token_urlsafe(32))"

# Generate token encryption key
python -c "from cryptography.fernet import Fernet; print('TOKEN_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

Add these to your `.env` file for persistent token storage.

## Need More Help?

- 📖 Full documentation: [README_OAUTH_PROXY.md](./README_OAUTH_PROXY.md)
- 🔄 Migration guide: [MIGRATION.md](./MIGRATION.md)
- 📝 Implementation details: [IMPLEMENTATION_SUMMARY.md](./IMPLEMENTATION_SUMMARY.md)

---

**You're all set! Happy posting! 🚀**
