"""Tests for search_vulnerabilities_by_cve function."""

from unittest.mock import Mock

import pytest

from helix_tenable_mcp.server import search_vulnerabilities_by_cve


class TestSearchVulnerabilitiesByCVE:
    """Test suite for search_vulnerabilities_by_cve function."""

    def test_search_with_valid_cve(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test searching for vulnerabilities with a valid CVE ID."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_cve("CVE-2025-55182")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"
        assert result["total_findings"] == 1
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["plugin_id"] == 123456
        assert result["vulnerabilities"][0]["plugin_name"] == "Test Vulnerability"
        assert result["vulnerabilities"][0]["severity"] == 4
        assert result["vulnerabilities"][0]["severity_name"] == "Critical"

        # Verify correct API call
        mock_tenable_client.workbenches.vulns.assert_called_once_with(
            filter=('plugin.attributes.cve', 'eq', 'CVE-2025-55182')
        )

    def test_search_normalizes_cve_id_without_prefix(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that CVE ID without 'CVE-' prefix is normalized."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_cve("2025-55182")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"
        mock_tenable_client.workbenches.vulns.assert_called_once_with(
            filter=('plugin.attributes.cve', 'eq', 'CVE-2025-55182')
        )

    def test_search_normalizes_lowercase_cve(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that lowercase CVE ID is normalized to uppercase."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_cve("cve-2025-55182")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"
        mock_tenable_client.workbenches.vulns.assert_called_once_with(
            filter=('plugin.attributes.cve', 'eq', 'CVE-2025-55182')
        )

    def test_search_strips_whitespace(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that whitespace is stripped from CVE ID."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_cve("  CVE-2025-55182  ")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"

    def test_search_with_no_results(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test searching for a CVE with no results."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = []

        # Act
        result = search_vulnerabilities_by_cve("CVE-9999-99999")

        # Assert
        assert result["cve_id"] == "CVE-9999-99999"
        assert result["total_findings"] == 0
        assert result["vulnerabilities"] == []

    def test_search_with_multiple_results(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test searching for a CVE that returns multiple vulnerabilities."""
        # Arrange
        vuln1 = sample_vuln_data.copy()
        vuln2 = sample_vuln_data.copy()
        vuln2["plugin_id"] = 123457
        vuln2["plugin_name"] = "Another Vulnerability"
        mock_tenable_client.workbenches.vulns.return_value = [vuln1, vuln2]

        # Act
        result = search_vulnerabilities_by_cve("CVE-2025-55182")

        # Assert
        assert result["cve_id"] == "CVE-2025-55182"
        assert result["total_findings"] == 2
        assert len(result["vulnerabilities"]) == 2
        assert result["vulnerabilities"][0]["plugin_id"] == 123456
        assert result["vulnerabilities"][1]["plugin_id"] == 123457

    def test_search_includes_vpr_score(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that VPR score is included if present."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_cve("CVE-2025-55182")

        # Assert
        vuln = result["vulnerabilities"][0]
        assert "count" in vuln
        assert vuln["count"] == 5

    def test_search_handles_api_error(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test error handling when API call fails."""
        # Arrange
        mock_tenable_client.workbenches.vulns.side_effect = Exception("API Error")

        # Act
        result = search_vulnerabilities_by_cve("CVE-2025-55182")

        # Assert
        assert "error" in result
        assert result["error"] == "API Error"
        assert result["cve_id"] == "CVE-2025-55182"

    def test_search_handles_missing_optional_fields(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test that missing optional fields don't cause errors."""
        # Arrange
        minimal_vuln = {
            "plugin_id": 123456,
            "plugin_name": "Test Vulnerability",
            "severity": 4,
        }
        mock_tenable_client.workbenches.vulns.return_value = [minimal_vuln]

        # Act
        result = search_vulnerabilities_by_cve("CVE-2025-55182")

        # Assert
        assert result["total_findings"] == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["plugin_id"] == 123456
        assert vuln["severity_name"] is None
        assert vuln["count"] is None
