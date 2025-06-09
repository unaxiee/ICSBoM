import tempfile
import requests
import shutil
import pickle
import hashlib
import threading
from pathlib import Path, PurePath
from typing import List, Dict, Optional
from util.parse_package_archive import parse_archlinux_files
from util import cache_logging, config


class PackageDB:
    """
    Downloads and parses Arch Linux package tarballs and provides filename-based lookup.
    Supports persistent caching via pickled object based on input hash.
    Lazy-loads the dataset only on first use.
    """
    _lock = threading.Lock()

    def __init__(self, urls: Optional[List[str]] = None, local_paths: Optional[List[str]] = None,
                 cache_dir: Optional[Path] = None):
        """
        Args:
            urls (List[str]): URLs to download tarballs from.
            local_paths (List[str]): File paths to existing tarballs.
            cache_dir (Path, optional): Directory to store the pickle cache.
        """
        self.urls = urls or []
        self.local_paths = [PurePath(p) for p in (local_paths or [])]
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_paths: List[PurePath] = []
        self.filename_to_package: Dict[str, str] = {}
        self.filenames: List[str] = []
        self._loaded = False
        self.cache_dir = Path(cache_dir) if cache_dir else Path(".packagedb_cache")

    def _compute_cache_key(self) -> str:
        """Compute a unique hash key based on input URLs and paths."""
        hasher = hashlib.sha256()
        for item in sorted(self.urls + [str(p) for p in self.local_paths]):
            hasher.update(item.encode("utf-8"))
        return hasher.hexdigest()

    def _load_or_initialize(self):
        """Load from pickle cache or perform full initialization."""
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return
            self._loaded = True
            cache_key = self._compute_cache_key()
            self.cache_dir.mkdir(exist_ok=True)
            cache_path = self.cache_dir / f"{cache_key}.pkl"

            if cache_path.exists():
                with open(cache_path, "rb") as f:
                    data = pickle.load(f)
                    self.filename_to_package = data["filename_to_package"]
                    self.filenames = data["filenames"]
                # Record cache hit
                if config.LOG_CACHE_PERFORMANCE:
                    cache_logging.record_hit("packagedb")
                return

            # Record cache miss
            if config.LOG_CACHE_PERFORMANCE:
                cache_logging.record_miss("packagedb")
            self._initialize()

            with open(cache_path, "wb") as f:
                pickle.dump({
                    "filename_to_package": self.filename_to_package,
                    "filenames": self.filenames
                }, f)

    def _initialize(self):
        """Download tarballs and build filename mappings."""
        for url in self.urls:
            local_path = Path(self.temp_dir.name) / Path(url).name
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                with open(local_path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)
            self.temp_paths.append(PurePath(local_path))

        all_tar_paths = self.local_paths + self.temp_paths
        package_data = parse_archlinux_files(all_tar_paths)

        for package, filenames in package_data.items():
            for fname in filenames:
                if fname not in self.filename_to_package:
                    self.filename_to_package[fname] = package
                    self.filenames.append(fname)

    def lookup_exact(self, filename: str) -> Optional[str]:
        """Return the package name for an exact filename match."""
        self._load_or_initialize()
        return self.filename_to_package.get(filename)

    def search_substring(self, needle: str) -> List[str]:
        """Return list of filenames that contain the given substring."""
        self._load_or_initialize()
        return [s for s in self.filenames if needle in s]

    def initialize(self):
        """Force initialization of the database."""
        self._load_or_initialize()
        return self


    def __del__(self):
        """Cleanup temporary directory when the object is destroyed."""
        self.temp_dir.cleanup()
