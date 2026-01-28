"""Shared pytest fixtures for Helix Tenable MCP tests."""

import os
from typing import Any
from unittest.mock import Mock, patch

import pytest


@pytest.fixture
def mock_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required environment variables for testing."""
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "test-access-key")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "test-secret-key")


@pytest.fixture
def mock_tenable_client() -> Mock:
    """Create a mock Tenable.io client."""
    client = Mock()
    client.workbenches = Mock()
    client.plugins = Mock()
    return client


@pytest.fixture
def sample_vuln_data() -> dict[str, Any]:
    """Sample vulnerability data from Tenable API."""
    return {
        "plugin_id": 123456,
        "plugin_name": "Test Vulnerability",
        "severity": 4,
        "severity_name": "Critical",
        "count": 5,
        "vulnerability_state": "Open",
        "accepted_count": 0,
        "recasted_count": 0,
        "vpr": {"score": 9.5},
    }


@pytest.fixture
def sample_plugin_details() -> dict[str, Any]:
    """Sample plugin details from Tenable API."""
    return {
        "id": 123456,
        "name": "Test Vulnerability",
        "family_name": "Web Servers",
        "risk_factor": "Critical",
        "cvss_base_score": 9.8,
        "cvss3_base_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "This is a test vulnerability description.",
        "solution": "Update to the latest version.",
        "synopsis": "Remote code execution vulnerability",
        "attributes": {
            "cve": ["CVE-2025-55182"]
        },
        "exploit_available": True,
        "exploitability_ease": "Exploits are available",
        "patch_publication_date": "2025-01-15",
        "vulnerability_publication_date": "2025-01-10",
        "see_also": ["https://example.com/advisory"],
    }


@pytest.fixture
def sample_asset_data() -> dict[str, Any]:
    """Sample asset data from Tenable API."""
    return {
        "uuid": "12345678-1234-1234-1234-123456789012",
        "fqdn": "test.example.com",
        "hostname": "test",
        "ipv4": "192.0.2.1",
        "operating_system": ["Ubuntu 22.04"],
        "severity": 4,
        "severity_name": "Critical",
        "first_seen": "2025-01-20T10:00:00Z",
        "last_seen": "2025-01-28T10:00:00Z",
    }


@pytest.fixture
def patch_get_tenable_client(mock_tenable_client: Mock) -> Any:
    """Patch the get_tenable_client function to return mock client."""
    with patch(
        "helix_tenable_mcp.server.get_tenable_client",
        return_value=mock_tenable_client
    ) as mock_get_client:
        yield mock_get_client
