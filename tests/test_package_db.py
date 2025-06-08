import pytest
import tarfile
import shutil
from pathlib import Path
from util.PackageDB import PackageDB

@pytest.fixture
def test_packagedb_cache(tmp_path):
    tar_path = Path(__file__).resolve().parent / "test_packagedb_cache.tar"
    with tarfile.open(tar_path, "r") as tar:
        tar.extractall(tmp_path, filter="data")
    yield tmp_path
    shutil.rmtree(tmp_path)

def get_test_archive_path():
    base_dir = Path(__file__).resolve().parent
    return base_dir / "test_parse_package_archive.tar.gz"


def test_initialize_and_exact_lookup(test_packagedb_cache):
    """Test PackageDB initializes and provides exact filename lookups."""
    archive_path = get_test_archive_path()
    db = PackageDB(local_paths=[str(archive_path)], cache_dir=test_packagedb_cache)
    # Test full path lookup
    assert db.lookup_exact("/usr/bin/tool.sh") == "pkg-02"
    assert db.lookup_exact("tool.sh") == "pkg-02"
    assert db.lookup_exact("runner.sh") == "pkg-02"
    assert db.lookup_exact("nonexistent.binary") is None


def test_substring_search(test_packagedb_cache):
    """Test substring search returns expected filenames."""
    archive_path = get_test_archive_path()
    db = PackageDB(local_paths=[str(archive_path)], cache_dir=test_packagedb_cache)

    matches = db.search_substring("run")
    assert any("/usr/bin/run" in m for m in matches)
    assert any("runner.sh" in m for m in matches)

    go_matches = db.search_substring(".go")
    assert len(go_matches) >= 2
    assert all(".go" in m for m in go_matches)