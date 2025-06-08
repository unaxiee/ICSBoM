import tarfile
import os
from collections import defaultdict
from pathlib import PurePath
from typing import List, Dict, Set, Optional

ALLOWED_EXTENSIONS = {
    '.so', '.out', '.elf', '.axf', '.prx', '.puff', '.mod', '.ko', '.la', '.a', '.run', '.appimage',
    '.shar', '.mojo', '.install', '.sh', '.bash', '.zsh', '.py', '.pl', '.rb', '.js', '.php', '.exp',
    '.cgi', '.fcgi', '.svc', '.hex', '.srec', '.img', '.iso', '.dylib', '.apk', '.desktop', '.service',
    '.target', '.command', '.jar', '.class', '.wasm', '.pex', '.ts', '.go', '.java', '.rs', '.lua',
    '.pyc', '.pm', '.woff', '.woff2'
}

SPECIAL_FILENAMES = {'configure', 'install', 'start', 'run', 'launch'}
EXCLUDED_SUFFIXES = ('.tar', '.gz', '.tar.gz')


def extract_package_name(desc_lines: List[str]) -> Optional[str]:
    for i, line in enumerate(desc_lines):
        if line == "%NAME%" and i + 1 < len(desc_lines):
            return desc_lines[i + 1].strip()
    return None


def is_relevant_file(path: str) -> bool:
    if path.endswith(EXCLUDED_SUFFIXES) or path.endswith('/'):
        return False
    ext = os.path.splitext(path)[1]
    filename = os.path.basename(path)
    return (
        ext in ALLOWED_EXTENSIONS or
        '/bin/' in path or '/sbin/' in path or
        filename in SPECIAL_FILENAMES
    )


def extract_files(files_lines: List[str]) -> Set[str]:
    result = set()
    in_files_section = False
    for line in files_lines:
        if line == "%FILES%":
            in_files_section = True
            continue
        if in_files_section and is_relevant_file(line):
            result.add(line)
    return result


def parse_archlinux_files(tar_paths: List[PurePath]) -> Dict[str, Set[str]]:
    """Parse Arch Linux tarballs containing both desc and files for each package.

    Args:
        tar_paths (List[str]): List of tarball paths to parse.

    Returns:
        Dict[str, Set[str]]: Mapping of package names to sets of filtered file paths.
    """
    packages: Dict[str, Set[str]] = defaultdict(set)

    for tar_path in tar_paths:
        with tarfile.open(tar_path, 'r:gz') as tar:
            members = {m.name: m for m in tar.getmembers()}

            for member_name in members:
                # only start from the desc file to find the correct package name
                # the files is read in the same dir
                if not member_name.endswith('/desc'):
                    continue

                package_dir = member_name.rsplit('/', 1)[0]
                desc_member = tar.extractfile(members[member_name])
                if not desc_member:
                    continue

                desc_lines = desc_member.read().decode('utf-8').splitlines()
                package_name = extract_package_name(desc_lines)
                if not package_name:
                    continue

                files_member_name = f"{package_dir}/files"
                if files_member_name not in members:
                    continue

                files_member = tar.extractfile(members[files_member_name])
                if not files_member:
                    continue

                files_lines = files_member.read().decode('utf-8').splitlines()
                packages[package_name].update(extract_files(files_lines))

    return packages