from util.parse_package_archive import parse_archlinux_files, ALLOWED_EXTENSIONS, SPECIAL_FILENAMES
import os
from pathlib import PurePath

db_tar_path = PurePath(os.path.dirname(__file__)) / 'test_parse_package_archive.tar.gz'

def test_parse_archlinux_files():
    result = parse_archlinux_files([db_tar_path])
    assert isinstance(result, dict), "Result should be a dictionary"
    assert len(result) > 0, "Should contain at least one package"
    for pkg, files in result.items():
        assert isinstance(pkg, str), "Package name should be a string"
        assert isinstance(files, set), "Files should be stored in a set"
        for f in files:
            assert isinstance(f, str), "File paths should be strings"
            assert not f.endswith('/'), "Directory entries should not be included"

def test_expected_extensions_present():
    result = parse_archlinux_files([db_tar_path])
    found_extensions = set()
    for files in result.values():
        for f in files:
            found_extensions.add(PurePath(f).suffix.lower())
    missing = ALLOWED_EXTENSIONS - found_extensions
    message = f"Missing extensions: {sorted(missing)}\nFound extensions: {sorted(found_extensions)}"
    assert missing == set(), message

def test_excluded_extensions_absent():
    result = parse_archlinux_files([db_tar_path])
    excluded = {'.c', '.cpp', '.h', '.hpp', '.gz', '.html', '.txt', '.conf', '.zst'}
    for files in result.values():
        for f in files:
            assert os.path.splitext(f)[1] not in excluded, f"Excluded extension present: {f}"

def test_executable_paths():
    result = parse_archlinux_files([db_tar_path])
    matched = any('/bin/' in f or '/sbin/' in f for files in result.values() for f in files)
    assert matched, "At least one file should be in /bin/ or /sbin/ paths"

def test_special_filenames():
    result = parse_archlinux_files([db_tar_path])
    found = any(os.path.basename(f) in SPECIAL_FILENAMES for files in result.values() for f in files)
    assert found, "At least one known executable-style filename should be included"
