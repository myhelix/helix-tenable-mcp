# Helix Tenable MCP Server

MCP server for Tenable.io vulnerability management integration. Provides tools to query vulnerabilities, CVEs, and affected assets directly from Claude Code.

## Features

- Search vulnerabilities by CVE ID
- Get detailed vulnerability plugin information
- List assets affected by specific CVEs
- Search vulnerabilities by severity level
- Direct integration with Tenable.io cloud platform

## Prerequisites

- Python 3.10 or higher
- Tenable.io account with API access
- Access Key and Secret Key from Tenable.io

## Installation

### Using UV (Recommended)

```bash
# Clone the repository
cd ~/dev
git clone <repository-url> helix-tenable-mcp
cd helix-tenable-mcp

# Install dependencies
uv pip install -e .
```

### Using pip

```bash
pip install -e .
```

## Configuration

### 1. Get Tenable.io API Keys

1. Log in to your Tenable.io account at https://cloud.tenable.com
2. Navigate to **Settings** → **My Account** → **API Keys**
3. Click **Generate** to create a new API key pair
4. Copy the Access Key and Secret Key (you won't be able to see the Secret Key again)

### 2. Set Environment Variables

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```
TENABLE_ACCESS_KEY=your-access-key-here
TENABLE_SECRET_KEY=your-secret-key-here
```

**Security Note**: Never commit `.env` to version control. It's already in `.gitignore`.

### 3. Configure Claude Code

Add the MCP server to your Claude Code settings:

```bash
claude mcp add helix-tenable-mcp -s user \
  -e UV_PYTHON="3.13" \
  -- uvx --from /Users/YOUR_USERNAME/dev/helix-tenable-mcp helix-tenable-mcp
```

Or manually edit your Claude Code MCP settings (`~/.config/claude/config.json`):

```json
{
  "mcpServers": {
    "helix-tenable-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "/Users/YOUR_USERNAME/dev/helix-tenable-mcp",
        "helix-tenable-mcp"
      ],
      "env": {
        "UV_PYTHON": "3.13",
        "TENABLE_ACCESS_KEY": "your-access-key",
        "TENABLE_SECRET_KEY": "your-secret-key"
      }
    }
  }
}
```

**Note**: Replace `YOUR_USERNAME` with your actual username.

## Usage

Once configured, you can use the following tools in Claude Code:

### Search by CVE

```
Search for CVE-2025-55182 in Tenable
```

This uses the `search_vulnerabilities_by_cve` tool to find all instances of the vulnerability.

### Get Vulnerability Details

```
Get details for Tenable plugin ID 123456
```

Uses `get_vulnerability_details` to retrieve comprehensive information about a specific plugin.

### List Affected Assets

```
Show me all assets affected by CVE-2025-55182
```

Uses `list_affected_assets` to get a list of hosts with the vulnerability.

### Search by Severity

```
Show me critical vulnerabilities in Tenable
```

Uses `search_vulnerabilities_by_severity` to filter by severity level.

## Available Tools

### `search_vulnerabilities_by_cve(cve_id: str)`

Search for vulnerabilities by CVE ID.

**Parameters:**
- `cve_id` (string): CVE identifier (e.g., 'CVE-2025-55182')

**Returns:**
- Total findings count
- List of vulnerabilities with asset details

### `get_vulnerability_details(plugin_id: int)`

Get detailed information about a vulnerability plugin.

**Parameters:**
- `plugin_id` (integer): Tenable plugin ID

**Returns:**
- Plugin metadata
- CVSS scores and vectors
- Description and solution
- Related CVEs
- Exploit availability

### `list_affected_assets(cve_id: str)`

List all assets affected by a specific CVE.

**Parameters:**
- `cve_id` (string): CVE identifier

**Returns:**
- Total affected assets count
- Asset details (hostname, IP, OS, severity, state)

### `search_vulnerabilities_by_severity(severity: str, limit: int = 100)`

Search for vulnerabilities by severity level.

**Parameters:**
- `severity` (string): Severity level (Critical, High, Medium, Low, Info)
- `limit` (integer): Maximum results to return (default: 100)

**Returns:**
- List of vulnerabilities matching severity level

## Development

### Running Tests

```bash
uv run pytest
```

### Code Quality

```bash
# Format code
uv run black .

# Lint
uv run ruff check .

# Type checking
uv run mypy src/helix_tenable_mcp
```

## Troubleshooting

### "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY must be set"

Make sure you've:
1. Created the `.env` file with your keys
2. Or set the environment variables in Claude Code MCP settings

### Connection Errors

Verify:
- You can access https://cloud.tenable.com from your network
- Your API keys are valid and not expired
- Your Tenable.io account has appropriate permissions

### SSL Certificate Issues (Netskope)

If using Netskope with SSL inspection, add to your MCP config:

```json
{
  "env": {
    "SSL_CERT_FILE": "/Users/YOUR_USERNAME/.config/certs/nscacert_combined.pem"
  }
}
```

See [Claude Code Configuration](../CLAUDE.md) for Netskope setup.

## References

- [Tenable.io API Documentation](https://developer.tenable.com/docs)
- [pyTenable Documentation](https://pytenable.readthedocs.io/)
- [MCP Documentation](https://modelcontextprotocol.io/)
- [Claude Code MCP Guide](https://docs.anthropic.com/claude/docs/model-context-protocol)

## License

MIT
