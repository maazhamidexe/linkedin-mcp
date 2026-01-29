# LinkedIn MCP Server

Post to LinkedIn directly from Claude Desktop with support for text and media attachments.

## Features

- Post text updates to LinkedIn
- Attach images and videos to posts
- Control post visibility (public/connections)
- OAuth2 authentication flow
- Secure token storage

## Tools

- `authenticate`: Authenticate with LinkedIn
- `create_post`: Create and share posts optionally with media attachments
  - state the file path to the relevant media file to attach it to the post

## Setup


## Development
Clone the repository and install the package in editable mode:
   ```bash
   git clone https://github.com/maazhamidexe/linkedin-mcp.git
   cd linkedin-mcp
   uv venv
   ```
Run the server from development directory:

```json
{
  "mcpServers": {
    "linkedin": {
      "url": "http://localhost:8000/mcp"
    }
  }
}
```
   

## License
MIT License
