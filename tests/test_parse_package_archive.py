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

def test_basename_and_full_path_included():
    result = parse_archlinux_files([db_tar_path])
    found_basenames = set()
    found_fullpaths = set()

    for files in result.values():
        for f in files:
            if '/' in f:
                found_fullpaths.add(f)
            else:
                found_basenames.add(f)

    # These are the synthetic files added in /usr/bin/
    expected_filenames = {
        'test_program.go',
        'test_program.java',
        'test_program.js',
        'test_program.lua',
        'test_program.pl',
    }

    # Check that both the full path and the basename are present
    missing_basenames = expected_filenames - found_basenames
    missing_fullpaths = {f"/usr/bin/{name}" for name in expected_filenames} - found_fullpaths

    assert not missing_basenames, f"Missing basenames: {missing_basenames}"
    assert not missing_fullpaths, f"Missing full paths: {missing_fullpaths}"
