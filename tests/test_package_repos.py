"""Tests for package_repos.py module.

This module contains tests for the package_repos.py module, specifically for the
version_res_arch_local function. It uses the same cache strategy as test_package_repo_scraper.py
to ensure consistent test results without network requests.

Note that test cache dir as an arg for each test forces the mock cache init.
"""

import pytest
from typing import List

from util.package_repos import version_res_arch_local
from tests.test_package_repo_scraper import test_cache_dir  # Reuse the fixture


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