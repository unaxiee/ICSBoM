"""Tests for package_repos.py module.

This module contains tests for the package_repos.py module, specifically for the
version_res_arch_local and match_binary_to_package functions. It uses the same cache strategy 
as test_package_repo_scraper.py to ensure consistent test results without network requests.

Note that test cache dir as an arg for each test forces the mock cache init.
"""

import pytest
from typing import List
import unittest.mock as mock

from util.package_repos import version_res_arch_local, match_binary_to_package
from tests.test_package_repo_scraper import test_cache_dir  # Reuse the fixture
from tests.test_package_db import test_packagedb_cache, get_test_archive_path  # Reuse fixtures


@pytest.mark.integration
class TestVersionResArchLocal:
    """Tests for version_res_arch_local function."""

    @pytest.mark.parametrize("filename, candidate_versions, expected_version", [
        # Test with a MySQL-related filename
        ("mysql", ["5.7.21", "5.7.22", "5.7.23"], "5.7.21"),
        # Test with a library name
        ("mysql.so", ["5.7.21", "5.7.22", "5.7.23"], "5.7.21"),
        # Test with a more specific package name
        ("mysql-workbench", ["5.3.133", "5.3.2.1", "18.0.22"], "5.3.2.1"),
    ])
    def test_version_resolution(self, test_cache_dir, filename: str, candidate_versions: List[str], expected_version: str):
        """Test that version_res_arch_local correctly resolves versions.

        Args:
            test_cache_dir: Fixture that sets up the test cache directory
            filename: The filename to resolve versions for
            candidate_versions: List of candidate versions to choose from
            expected_version: The expected version that should be chosen
        """
        result = version_res_arch_local(filename, candidate_versions)

        assert result == expected_version, f"Expected {expected_version}, got {result}"

    def test_with_no_matches(self, test_cache_dir):
        """Test version_res_arch_local with a filename that has no matches."""
        filename = "nonexistent_package"
        candidate_versions = ["1.0.0", "2.0.0"]

        result = version_res_arch_local(filename, candidate_versions)

        assert result == "None", f"Expected None, got {result}"

    def test_with_multiple_filenames(self, test_cache_dir):
        """Test version_res_arch_local with a filename that generates multiple queries."""
        # Use a filename that will generate multiple queries (with .so and without)
        filename = "libgda-mysql.so.5.2.4.7"
        candidate_versions = ["5.7.21", "5.7.22", "5.2.4.7"]

        result = version_res_arch_local(filename, candidate_versions)

        assert result == "5.2.4.7", f"Expected 5.2.4.7, got {result}"


@pytest.mark.integration
class TestMatchBinaryToPackage:
    """Tests for match_binary_to_package function."""

    def test_match_binary_to_package(self, test_packagedb_cache):
        """Test that match_binary_to_package correctly matches a binary to a package."""
        with mock.patch('util.package_repos._package_db') as mock_instance:
            # Configure the mock
            mock_instance.search_substring.return_value = ["/usr/bin/tool.sh", "/usr/bin/runner.sh"]
            mock_instance.lookup_exact.side_effect = lambda x: "pkg-02" if x in ["/usr/bin/tool.sh", "/usr/bin/runner.sh"] else None

            # Call the function
            result = match_binary_to_package("tool")

            # Verify the result
            assert result == "pkg-02", f"Expected pkg-02, got {result}"

            # Verify the mock was called correctly
            mock_instance.search_substring.assert_called_once_with("tool")
            assert mock_instance.lookup_exact.call_count == 2

    def test_match_binary_to_package_no_matches(self, test_packagedb_cache):
        """Test that match_binary_to_package returns None when no matches are found."""
        with mock.patch('util.package_repos._package_db') as mock_instance:
            # Configure the mock
            mock_instance.search_substring.return_value = []

            # Call the function
            result = match_binary_to_package("nonexistent")

            # Verify the result
            assert result is None, f"Expected None, got {result}"

            # Verify the mock was called correctly
            mock_instance.search_substring.assert_called_once_with("nonexistent")
            assert mock_instance.lookup_exact.call_count == 0

    def test_match_binary_to_package_no_package_matches(self, test_packagedb_cache):
        """Test that match_binary_to_package correctly matches a binary to a package."""
        with mock.patch('util.package_repos._package_db') as mock_instance:
            # Configure the mock
            mock_instance.search_substring.return_value = ["/usr/bin/tool.sh", "/usr/bin/runner.sh"]
            # Always return a package for filenames returned by search_substring
            mock_instance.lookup_exact.side_effect = lambda x: "pkg-03" if x in ["/usr/bin/tool.sh", "/usr/bin/runner.sh"] else None

            # Call the function
            result = match_binary_to_package("tool")

            # Verify the result
            assert result == "pkg-03", f"Expected pkg-03, got {result}"

            # Verify the mock was called correctly
            mock_instance.search_substring.assert_called_once_with("tool")
            assert mock_instance.lookup_exact.call_count == 2
