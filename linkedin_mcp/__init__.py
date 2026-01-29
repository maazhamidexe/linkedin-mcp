"""LinkedIn MCP Server Package.

This package provides a Model Context Protocol (MCP) server for LinkedIn integration
using FastMCP's OAuth Proxy for authentication.

Features:
- OAuth 2.0 authentication via FastMCP OAuthProxy
- LinkedIn profile retrieval
- LinkedIn post creation (text and with media/links)

Usage:
    Run the server: linkedin-mcp
    Connect MCP client to: http://localhost:8000/sse
"""
import logging

# Set up a null handler to avoid "No handler found" warnings
logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.2.0"
