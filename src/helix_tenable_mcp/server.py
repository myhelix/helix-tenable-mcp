"""Helix Tenable MCP Server - Main server implementation."""

import os
from typing import Any

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from tenable.io import TenableIO

# Load environment variables
load_dotenv()

# Initialize MCP Server
mcp = FastMCP("helix-tenable-mcp")

# Initialize Tenable.io client
def get_tenable_client() -> TenableIO:
    """Get or create Tenable.io client."""
    access_key = os.getenv("TENABLE_ACCESS_KEY")
    secret_key = os.getenv("TENABLE_SECRET_KEY")

    if not access_key or not secret_key:
        raise ValueError(
            "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY must be set in environment"
        )

    return TenableIO(access_key=access_key, secret_key=secret_key)


@mcp.tool()
def search_vulnerabilities_by_cve(cve_id: str) -> dict[str, Any]:
    """
    Search for vulnerabilities by CVE ID in Tenable.io.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2025-55182')

    Returns:
        Dictionary containing vulnerability details and affected assets
    """
    client = get_tenable_client()

    # Normalize CVE ID
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    try:
        # Use workbenches API to search for vulnerabilities by CVE
        vulns = client.workbenches.vulns(
            filter=('plugin.attributes.cve', 'eq', cve_id)
        )

        results = []
        for vuln in vulns:
            results.append({
                "plugin_id": vuln.get("plugin_id"),
                "plugin_name": vuln.get("plugin_name"),
                "severity": vuln.get("severity"),
                "severity_name": vuln.get("severity_name"),
                "count": vuln.get("count"),
                "vulnerability_state": vuln.get("vulnerability_state"),
                "accepted_count": vuln.get("accepted_count"),
                "recasted_count": vuln.get("recasted_count"),
            })

        return {
            "cve_id": cve_id,
            "total_findings": len(results),
            "vulnerabilities": results
        }

    except Exception as e:
        return {
            "error": str(e),
            "cve_id": cve_id
        }


@mcp.tool()
def get_vulnerability_details(plugin_id: int) -> dict[str, Any]:
    """
    Get detailed information about a vulnerability plugin.

    Args:
        plugin_id: Tenable plugin ID

    Returns:
        Dictionary containing detailed plugin information
    """
    client = get_tenable_client()

    try:
        plugin = client.plugins.plugin_details(plugin_id)

        return {
            "plugin_id": plugin.get("id"),
            "name": plugin.get("name"),
            "family": plugin.get("family_name"),
            "severity": plugin.get("risk_factor"),
            "cvss_base_score": plugin.get("cvss_base_score"),
            "cvss3_base_score": plugin.get("cvss3_base_score"),
            "cvss_vector": plugin.get("cvss_vector"),
            "cvss3_vector": plugin.get("cvss3_vector"),
            "description": plugin.get("description"),
            "solution": plugin.get("solution"),
            "synopsis": plugin.get("synopsis"),
            "cve": plugin.get("attributes", {}).get("cve", []),
            "exploit_available": plugin.get("exploit_available"),
            "exploitability_ease": plugin.get("exploitability_ease"),
            "patch_publication_date": plugin.get("patch_publication_date"),
            "vulnerability_publication_date": plugin.get("vulnerability_publication_date"),
            "see_also": plugin.get("see_also", []),
        }

    except Exception as e:
        return {
            "error": str(e),
            "plugin_id": plugin_id
        }


@mcp.tool()
def list_affected_assets(cve_id: str) -> dict[str, Any]:
    """
    List all assets affected by a specific CVE.

    Args:
        cve_id: CVE identifier (e.g., 'CVE-2025-55182')

    Returns:
        Dictionary containing list of affected assets
    """
    client = get_tenable_client()

    # Normalize CVE ID
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    try:
        # Use workbenches API to get vulnerabilities by CVE
        vulns = client.workbenches.vulns(
            filter=('plugin.attributes.cve', 'eq', cve_id)
        )

        # For each vulnerability plugin, get the affected assets
        all_assets = []
        for vuln in vulns:
            plugin_id = vuln.get("plugin_id")
            if plugin_id:
                # Get assets affected by this plugin
                try:
                    assets = client.workbenches.vuln_assets(plugin_id)
                    for asset in assets:
                        all_assets.append({
                            "uuid": asset.get("uuid"),
                            "fqdn": asset.get("fqdn"),
                            "hostname": asset.get("hostname"),
                            "ipv4": asset.get("ipv4"),
                            "operating_system": asset.get("operating_system", []),
                            "severity": asset.get("severity"),
                            "severity_name": asset.get("severity_name"),
                            "first_seen": asset.get("first_seen"),
                            "last_seen": asset.get("last_seen"),
                        })
                except Exception as e:
                    # Skip if we can't get assets for this plugin
                    continue

        # Remove duplicates by UUID
        unique_assets = {asset["uuid"]: asset for asset in all_assets if asset.get("uuid")}

        return {
            "cve_id": cve_id,
            "total_affected_assets": len(unique_assets),
            "assets": list(unique_assets.values())
        }

    except Exception as e:
        return {
            "error": str(e),
            "cve_id": cve_id
        }


@mcp.tool()
def search_vulnerabilities_by_severity(
    severity: str,
    limit: int = 100
) -> dict[str, Any]:
    """
    Search for vulnerabilities by severity level.

    Args:
        severity: Severity level (Critical, High, Medium, Low, Info)
        limit: Maximum number of results to return (default: 100)

    Returns:
        Dictionary containing vulnerability findings
    """
    client = get_tenable_client()

    severity_map = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }

    severity_value = severity_map.get(severity.lower())
    if severity_value is None:
        return {
            "error": f"Invalid severity. Must be one of: {', '.join(severity_map.keys())}",
            "severity": severity
        }

    try:
        # Use workbenches API to get vulnerabilities by severity
        vulns = client.workbenches.vulns(
            filter=('severity', 'eq', severity_value)
        )

        results = []
        for vuln in vulns:
            if len(results) >= limit:
                break

            results.append({
                "plugin_id": vuln.get("plugin_id"),
                "plugin_name": vuln.get("plugin_name"),
                "severity": vuln.get("severity"),
                "severity_name": vuln.get("severity_name"),
                "count": vuln.get("count"),
                "vulnerability_state": vuln.get("vulnerability_state"),
                "vpr_score": vuln.get("vpr", {}).get("score") if vuln.get("vpr") else None,
            })

        return {
            "severity": severity,
            "total_findings": len(results),
            "vulnerabilities": results
        }

    except Exception as e:
        return {
            "error": str(e),
            "severity": severity
        }


def main() -> None:
    """Run the MCP server."""
    # Verify environment variables are set
    if not os.getenv("TENABLE_ACCESS_KEY") or not os.getenv("TENABLE_SECRET_KEY"):
        print("ERROR: TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY must be set")
        print("Please create a .env file or set these environment variables")
        return

    # Run the server
    mcp.run()


if __name__ == "__main__":
    main()
