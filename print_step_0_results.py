#!/usr/bin/env python3
"""
Utility to print the results from the pickle file produced at the end of step 0.
Prints one binary per line in the format <package>: <file>-version.
Only prints binaries with identified version numbers and/or packages.
Skips binaries where both package is unknown and version is None.
"""

import sys
import pickle
from pathlib import Path
from typing import List, Dict, Any

def load_pickle_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Load a pickle file and return its contents.

    Args:
        file_path: Path to the pickle file

    Returns:
        The contents of the pickle file
    """
    try:
        with open(file_path, 'rb') as f:
            return pickle.load(f)
    except Exception as e:
        print(f"Error loading pickle file: {e}")
        sys.exit(1)

def select_pickle_file() -> str:
    """
    Find a pickle file in the util/fw_pkl directory.

    Returns:
        Path to the pickle file
    """
    pkl_dir = Path("util/fw_pkl")
    if not pkl_dir.exists():
        print(f"Error: Directory {pkl_dir} does not exist")
        sys.exit(1)
    pkl_files = list(pkl_dir.glob("*.pkl"))
    if not pkl_files:
        print(f"Error: No pickle files found in {pkl_dir}")
        sys.exit(1)
    return str(pkl_files[0])

def main():
    pickle_file = select_pickle_file()

    binaries = load_pickle_file(pickle_file)

    # Filter binaries to only include those with identified version numbers and/or packages
    identified_binaries = [b for b in binaries if 'version' in b or 'package_name' in b]

    for binary in identified_binaries:
        binary_name = binary.get('name', 'Unknown')
        version = binary.get('version', None)
        package_name = binary.get('package_name', 'Unknown')

        # Skip binaries where package is unknown and version is None
        if package_name == 'Unknown' and version is None:
            continue

        # Use 'Unknown' as the display value for None versions
        if version is None:
            version = 'Unknown'

        print(f"{package_name}: {binary_name}-{version}")

if __name__ == "__main__":
    main()
