#!/bin/bash

# Script to configure helix-tenable-mcp in Claude Code
# Prompts for Tenable.io API credentials securely

set -e

echo "=================================="
echo "Helix Tenable MCP Server Setup"
echo "=================================="
echo ""
echo "This script will configure the Tenable MCP server for Claude Code."
echo ""
echo "You'll need your Tenable.io API credentials."
echo "Get them from: https://cloud.tenable.com → Settings → API Keys"
echo ""

# Prompt for Access Key
read -p "Enter your Tenable Access Key: " ACCESS_KEY

if [ -z "$ACCESS_KEY" ]; then
    echo "Error: Access Key cannot be empty"
    exit 1
fi

# Prompt for Secret Key (hidden input)
echo ""
read -s -p "Enter your Tenable Secret Key (hidden): " SECRET_KEY
echo ""

if [ -z "$SECRET_KEY" ]; then
    echo "Error: Secret Key cannot be empty"
    exit 1
fi

echo ""
echo "Configuring MCP server..."
echo ""

# Add the MCP server to Claude Code
claude mcp add helix-tenable-mcp -s user \
  -e UV_PYTHON="3.13" \
  -e TENABLE_ACCESS_KEY="$ACCESS_KEY" \
  -e TENABLE_SECRET_KEY="$SECRET_KEY" \
  -- uvx --from /Users/ryan.niemes/dev/helix-tenable-mcp helix-tenable-mcp

echo ""
echo "✓ MCP server configured successfully!"
echo ""
echo "Next steps:"
echo "  1. Restart Claude Code to load the MCP server"
echo "  2. Test it with: 'Search Tenable for CVE-2025-55182'"
echo ""
