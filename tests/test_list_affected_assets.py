"""Tests for list_affected_assets function."""

from unittest.mock import Mock

import pytest

from helix_tenable_mcp.server import list_affected_assets


class TestListAffectedAssets:
    """Test suite for list_affected_assets function."""

    def test_list_assets_with_valid_cve(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test listing affected assets with a valid CVE ID."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]
        mock_tenable_client.workbenches.vuln_assets.return_value = [sample_asset_data]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"
        assert result["total_affected_assets"] == 1
        assert len(result["assets"]) == 1

        asset = result["assets"][0]
        assert asset["uuid"] == "12345678-1234-1234-1234-123456789012"
        assert asset["fqdn"] == "test.example.com"
        assert asset["hostname"] == "test"
        assert asset["ipv4"] == "192.0.2.1"
        assert asset["operating_system"] == ["Ubuntu 22.04"]
        assert asset["severity"] == 4
        assert asset["severity_name"] == "Critical"

        # Verify correct API calls
        mock_tenable_client.workbenches.vulns.assert_called_once_with(
            filter=('plugin.attributes.cve', 'eq', 'CVE-2025-55182')
        )
        mock_tenable_client.workbenches.vuln_assets.assert_called_once_with(123456)

    def test_list_assets_normalizes_cve_id(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test that CVE ID normalization works."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]
        mock_tenable_client.workbenches.vuln_assets.return_value = [sample_asset_data]

        # Act
        result = list_affected_assets("2025-55182")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"
        mock_tenable_client.workbenches.vulns.assert_called_once_with(
            filter=('plugin.attributes.cve', 'eq', 'CVE-2025-55182')
        )

    def test_list_assets_with_no_vulnerabilities(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test listing assets when CVE has no vulnerabilities."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = []

        # Act
        result = list_affected_assets("CVE-9999-99999")

        # Assert
        assert result["cve_id"] == "CVE-9999-99999"
        assert result["total_affected_assets"] == 0
        assert result["assets"] == []

        # vuln_assets should not be called since there are no vulnerabilities
        mock_tenable_client.workbenches.vuln_assets.assert_not_called()

    def test_list_assets_with_multiple_plugins(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test listing assets when multiple plugins are affected by same CVE."""
        # Arrange
        vuln1 = sample_vuln_data.copy()
        vuln2 = sample_vuln_data.copy()
        vuln2["plugin_id"] = 123457

        asset1 = sample_asset_data.copy()
        asset2 = sample_asset_data.copy()
        asset2["uuid"] = "87654321-4321-4321-4321-210987654321"
        asset2["fqdn"] = "test2.example.com"

        mock_tenable_client.workbenches.vulns.return_value = [vuln1, vuln2]
        mock_tenable_client.workbenches.vuln_assets.side_effect = [
            [asset1],
            [asset2],
        ]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        assert result["total_affected_assets"] == 2
        assert len(result["assets"]) == 2

        # Verify both plugins were queried
        assert mock_tenable_client.workbenches.vuln_assets.call_count == 2

    def test_list_assets_deduplicates_by_uuid(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test that duplicate assets (same UUID) are deduplicated."""
        # Arrange
        vuln1 = sample_vuln_data.copy()
        vuln2 = sample_vuln_data.copy()
        vuln2["plugin_id"] = 123457

        # Same asset appears in both vulnerabilities
        asset1 = sample_asset_data.copy()
        asset2 = sample_asset_data.copy()  # Same UUID

        mock_tenable_client.workbenches.vulns.return_value = [vuln1, vuln2]
        mock_tenable_client.workbenches.vuln_assets.side_effect = [
            [asset1],
            [asset2],
        ]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        assert result["total_affected_assets"] == 1  # Deduplicated
        assert len(result["assets"]) == 1

    def test_list_assets_handles_vuln_without_plugin_id(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_asset_data: dict,
    ) -> None:
        """Test handling when vulnerability doesn't have plugin_id."""
        # Arrange
        vuln_no_plugin = {"plugin_name": "Test Vulnerability"}
        mock_tenable_client.workbenches.vulns.return_value = [vuln_no_plugin]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        assert result["total_affected_assets"] == 0
        assert result["assets"] == []

        # vuln_assets should not be called without plugin_id
        mock_tenable_client.workbenches.vuln_assets.assert_not_called()

    def test_list_assets_continues_on_vuln_assets_error(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test that errors fetching assets for one plugin don't stop processing."""
        # Arrange
        vuln1 = sample_vuln_data.copy()
        vuln2 = sample_vuln_data.copy()
        vuln2["plugin_id"] = 123457

        mock_tenable_client.workbenches.vulns.return_value = [vuln1, vuln2]
        # First call fails, second succeeds
        mock_tenable_client.workbenches.vuln_assets.side_effect = [
            Exception("API Error"),
            [sample_asset_data],
        ]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        # Should still get results from second plugin
        assert result["total_affected_assets"] == 1
        assert len(result["assets"]) == 1

    def test_list_assets_handles_api_error(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test error handling when main API call fails."""
        # Arrange
        mock_tenable_client.workbenches.vulns.side_effect = Exception("API Error")

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        assert "error" in result
        assert result["error"] == "API Error"
        assert result["cve_id"] == "CVE-2025-55182"

    def test_list_assets_filters_assets_without_uuid(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test that assets without UUIDs are filtered out."""
        # Arrange
        asset_with_uuid = sample_asset_data.copy()
        asset_without_uuid = sample_asset_data.copy()
        asset_without_uuid["uuid"] = None

        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]
        mock_tenable_client.workbenches.vuln_assets.return_value = [
            asset_with_uuid,
            asset_without_uuid,
        ]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        assert result["total_affected_assets"] == 1  # Only asset with UUID
        assert result["assets"][0]["uuid"] == "12345678-1234-1234-1234-123456789012"

    def test_list_assets_includes_all_asset_fields(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        sample_asset_data: dict,
    ) -> None:
        """Test that all expected asset fields are included."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]
        mock_tenable_client.workbenches.vuln_assets.return_value = [sample_asset_data]

        # Act
        result = list_affected_assets("CVE-2025-55182")

        # Assert
        asset = result["assets"][0]
        expected_fields = [
            "uuid",
            "fqdn",
            "hostname",
            "ipv4",
            "operating_system",
            "severity",
            "severity_name",
            "first_seen",
            "last_seen",
        ]
        for field in expected_fields:
            assert field in asset, f"Missing expected field: {field}"
