"""
Test script to verify LinkedIn OAuth credentials
This will help diagnose the authentication issue
"""
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.getenv("LINKEDIN_CLIENT_ID")
CLIENT_SECRET = os.getenv("LINKEDIN_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/auth/callback"

print("=" * 60)
print("LinkedIn OAuth Credential Test")
print("=" * 60)
print(f"Client ID: {CLIENT_ID}")
print(f"Client Secret: {CLIENT_SECRET[:10]}..." if CLIENT_SECRET else "Client Secret: NOT SET")
print(f"Redirect URI: {REDIRECT_URI}")
print("=" * 60)

# Test 1: Check if credentials are set
if not CLIENT_ID or not CLIENT_SECRET:
    print("[ERROR] Credentials not set in .env file")
    exit(1)

print("\n[OK] Credentials loaded from .env")

# Test 2: Check for special characters that might cause issues
if '"' in CLIENT_SECRET or "'" in CLIENT_SECRET:
    print("[WARNING] Client secret contains quotes - this may cause issues")
    print(f"   Raw value: {repr(CLIENT_SECRET)}")
else:
    print("[OK] Client secret format looks good")

# Test 3: Try to fetch OIDC configuration
print("\nFetching LinkedIn OIDC configuration...")
try:
    response = httpx.get("https://www.linkedin.com/oauth/.well-known/openid-configuration")
    if response.status_code == 200:
        config = response.json()
        print("[OK] LinkedIn OIDC configuration fetched successfully")
        print(f"   Authorization endpoint: {config['authorization_endpoint']}")
        print(f"   Token endpoint: {config['token_endpoint']}")
        print(f"   Userinfo endpoint: {config['userinfo_endpoint']}")
    else:
        print(f"[ERROR] Failed to fetch OIDC config: {response.status_code}")
except Exception as e:
    print(f"[ERROR] Error fetching OIDC config: {e}")

# Test 4: Instructions for manual testing
print("\n" + "=" * 60)
print("MANUAL TEST INSTRUCTIONS")
print("=" * 60)
print("\n1. Go to this URL in your browser:")
auth_url = (
    f"https://www.linkedin.com/oauth/v2/authorization"
    f"?response_type=code"
    f"&client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&state=test123"
    f"&scope=openid%20profile%20email%20w_member_social"
)
print(f"\n{auth_url}\n")

print("2. After authorizing, LinkedIn will redirect you to:")
print(f"   {REDIRECT_URI}?code=AUTHORIZATION_CODE&state=test123")
print("\n3. Copy the 'code' parameter from the URL")
print("\n4. Test the token exchange with this curl command:")
print("\ncurl -X POST https://www.linkedin.com/oauth/v2/accessToken \\")
print("  -H 'Content-Type: application/x-www-form-urlencoded' \\")
print("  -d 'grant_type=authorization_code' \\")
print(f"  -d 'code=YOUR_CODE_HERE' \\")
print(f"  -d 'client_id={CLIENT_ID}' \\")
print(f"  -d 'client_secret={CLIENT_SECRET}' \\")
print(f"  -d 'redirect_uri={REDIRECT_URI}'")
print("\n5. If you get 'invalid_client', your credentials are wrong")
print("   If you get a token, the credentials work and the issue is in FastMCP")
print("=" * 60)
