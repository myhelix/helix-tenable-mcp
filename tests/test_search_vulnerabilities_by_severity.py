"""Tests for search_vulnerabilities_by_severity function."""

from unittest.mock import Mock

import pytest

from helix_tenable_mcp.server import search_vulnerabilities_by_severity


class TestSearchVulnerabilitiesBySeverity:
    """Test suite for search_vulnerabilities_by_severity function."""

    @pytest.mark.parametrize(
        "severity,expected_value",
        [
            ("Critical", 4),
            ("High", 3),
            ("Medium", 2),
            ("Low", 1),
            ("Info", 0),
        ],
    )
    def test_search_by_valid_severity(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
        severity: str,
        expected_value: int,
    ) -> None:
        """Test searching with valid severity levels."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_severity(severity)

        # Assert
        assert result["severity"] == severity
        assert result["total_findings"] == 1
        assert len(result["vulnerabilities"]) == 1

        # Verify correct API call with numeric severity value
        mock_tenable_client.workbenches.vulns.assert_called_once_with(
            filter=('severity', 'eq', expected_value)
        )

    def test_search_severity_case_insensitive(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that severity matching is case-insensitive."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act - try lowercase, uppercase, mixed case
        for severity_input in ["critical", "CRITICAL", "CrItIcAl"]:
            result = search_vulnerabilities_by_severity(severity_input)

            # Assert
            assert result["severity"] == severity_input
            assert "error" not in result

    def test_search_with_invalid_severity(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test error handling with invalid severity level."""
        # Act
        result = search_vulnerabilities_by_severity("SuperCritical")

        # Assert
        assert "error" in result
        assert "Invalid severity" in result["error"]
        assert result["severity"] == "SuperCritical"

        # API should not be called for invalid severity
        mock_tenable_client.workbenches.vulns.assert_not_called()

    def test_search_includes_expected_fields(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that result includes all expected fields."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_severity("Critical")

        # Assert
        vuln = result["vulnerabilities"][0]
        assert vuln["plugin_id"] == 123456
        assert vuln["plugin_name"] == "Test Vulnerability"
        assert vuln["severity"] == 4
        assert vuln["severity_name"] == "Critical"
        assert vuln["count"] == 5
        assert vuln["vulnerability_state"] == "Open"
        assert vuln["vpr_score"] == 9.5

    def test_search_with_custom_limit(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that custom limit parameter works correctly."""
        # Arrange
        # Create more vulnerabilities than the limit
        vulns = [sample_vuln_data.copy() for _ in range(10)]
        for i, vuln in enumerate(vulns):
            vuln["plugin_id"] = 123456 + i

        mock_tenable_client.workbenches.vulns.return_value = vulns

        # Act
        result = search_vulnerabilities_by_severity("Critical", limit=5)

        # Assert
        assert result["total_findings"] == 5  # Limited to 5
        assert len(result["vulnerabilities"]) == 5

    def test_search_default_limit(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that default limit is 100."""
        # Arrange
        # Create 150 vulnerabilities
        vulns = [sample_vuln_data.copy() for _ in range(150)]
        for i, vuln in enumerate(vulns):
            vuln["plugin_id"] = 123456 + i

        mock_tenable_client.workbenches.vulns.return_value = vulns

        # Act
        result = search_vulnerabilities_by_severity("Critical")

        # Assert
        assert result["total_findings"] == 100  # Default limit
        assert len(result["vulnerabilities"]) == 100

    def test_search_with_no_results(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test searching for severity with no results."""
        # Arrange
        mock_tenable_client.workbenches.vulns.return_value = []

        # Act
        result = search_vulnerabilities_by_severity("Info")

        # Assert
        assert result["severity"] == "Info"
        assert result["total_findings"] == 0
        assert result["vulnerabilities"] == []

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
        result = search_vulnerabilities_by_severity("Critical")

        # Assert
        assert "error" in result
        assert result["error"] == "API Error"
        assert result["severity"] == "Critical"

    def test_search_handles_missing_vpr_score(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test handling when VPR score is missing."""
        # Arrange
        sample_vuln_data["vpr"] = None
        mock_tenable_client.workbenches.vulns.return_value = [sample_vuln_data]

        # Act
        result = search_vulnerabilities_by_severity("Critical")

        # Assert
        assert result["total_findings"] == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["vpr_score"] is None

    def test_search_handles_missing_vpr_field(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test handling when VPR field is completely missing."""
        # Arrange
        vuln_without_vpr = {
            "plugin_id": 123456,
            "plugin_name": "Test Vulnerability",
            "severity": 4,
            "severity_name": "Critical",
            "count": 5,
            "vulnerability_state": "Open",
        }
        mock_tenable_client.workbenches.vulns.return_value = [vuln_without_vpr]

        # Act
        result = search_vulnerabilities_by_severity("Critical")

        # Assert
        assert result["total_findings"] == 1
        vuln = result["vulnerabilities"][0]
        assert vuln["vpr_score"] is None

    def test_search_respects_limit_with_fewer_results(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
        sample_vuln_data: dict,
    ) -> None:
        """Test that limit doesn't affect results when there are fewer than limit."""
        # Arrange
        vulns = [sample_vuln_data.copy() for _ in range(3)]
        for i, vuln in enumerate(vulns):
            vuln["plugin_id"] = 123456 + i

        mock_tenable_client.workbenches.vulns.return_value = vulns

        # Act
        result = search_vulnerabilities_by_severity("Critical", limit=100)

        # Assert
        assert result["total_findings"] == 3  # All 3 returned
        assert len(result["vulnerabilities"]) == 3

    def test_search_critical_vulnerabilities_real_scenario(
        self,
        mock_env_vars: None,
        mock_tenable_client: Mock,
        patch_get_tenable_client: Mock,
    ) -> None:
        """Test a realistic scenario with critical vulnerabilities."""
        # Arrange
        critical_vulns = [
            {
                "plugin_id": 200001,
                "plugin_name": "Apache Log4j RCE",
                "severity": 4,
                "severity_name": "Critical",
                "count": 10,
                "vulnerability_state": "Open",
                "vpr": {"score": 9.9},
            },
            {
                "plugin_id": 200002,
                "plugin_name": "OpenSSL Heartbleed",
                "severity": 4,
                "severity_name": "Critical",
                "count": 5,
                "vulnerability_state": "Open",
                "vpr": {"score": 9.5},
            },
        ]
        mock_tenable_client.workbenches.vulns.return_value = critical_vulns

        # Act
        result = search_vulnerabilities_by_severity("Critical", limit=10)

        # Assert
        assert result["total_findings"] == 2
        assert result["vulnerabilities"][0]["plugin_name"] == "Apache Log4j RCE"
        assert result["vulnerabilities"][1]["plugin_name"] == "OpenSSL Heartbleed"
        assert all(v["severity"] == 4 for v in result["vulnerabilities"])
