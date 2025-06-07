"""Package repository scraper module for retrieving package version information.

This module provides functions to scrape package repositories (primarily Arch Linux)
to retrieve version information for packages. It uses both archive.org and 
archive.archlinux.org as sources and implements a caching system to avoid 
repeated network requests.

The main entry point is the get_filename_versions function, which takes a filename
and returns a dictionary mapping package names to sets of version strings.
"""

import os
import re
import hashlib
import gzip
import json
import time
import asyncio
import httpx
from bs4 import BeautifulSoup
from internetarchive import ArchiveSession, Search
from typing import Set, Dict, List
from urllib.parse import quote
from tqdm.asyncio import tqdm as atqdm

CACHE_DIR = os.path.join(os.getcwd(), ".cache")
if os.path.isdir(CACHE_DIR):
    print(f"[debug] Using cache directory: {CACHE_DIR}")
else:
    print(f"[debug] Cache directory does not exist: {CACHE_DIR}")

ARCH_SUFFIX_RE = re.compile(
    r"-(x86_64|i686|any|aarch64|armv7h|armv6h|pentium4|riscv64|ppc64le|s390x|loongarch64)$"
)

SANITIZE_RE = re.compile(r"[@+.]")

def generate_prefix_variants(sanitized_name: str) -> Set[str]:
    """Generate all possible prefix variants for a sanitized package name.

    This function takes a package name where special characters have been replaced
    with underscores and generates all possible variants by replacing underscores
    with different separators (+, ., @, _).

    Args:
        sanitized_name (str): Package name with special characters replaced by underscores

    Returns:
        Set[str]: Set of all possible prefix variants
    """
    parts = sanitized_name.split('_')
    variants = set()
    def helper(i, path):
        if i == len(parts):
            variants.add(''.join(path))
            return
        if i > 0:
            for sep in ['+', '.', '@', '_']:
                helper(i + 1, path + [sep, parts[i]])
        else:
            helper(i + 1, [parts[i]])
    helper(0, [])
    return variants

def sanitize_package_name(pkg_name: str) -> str:
    """Sanitize a package name by replacing special characters with underscores.

    Args:
        pkg_name (str): Original package name

    Returns:
        str: Sanitized package name with special characters replaced by underscores
    """
    return SANITIZE_RE.sub("_", pkg_name)

def clean_filename(name: str) -> str:
    """Clean a package filename by removing architecture suffix and package extension.

    Args:
        name (str): Original package filename (e.g., "package-1.0-x86_64.pkg.tar.xz")

    Returns:
        str: Cleaned package name with architecture suffix and package extension removed
    """
    name = name.split(".pkg.tar")[0]
    return ARCH_SUFFIX_RE.sub("", name)

def is_cache_expired(path: str, max_age_days: int = 30) -> bool:
    """Check if a cache file is expired based on its creation time.

    Args:
        path (str): Path to the cache file
        max_age_days (int, optional): Maximum age in days before the cache is considered expired. 
            Defaults to 30.

    Returns:
        bool: True if the cache is expired or doesn't exist, False otherwise
    """
    if not os.path.exists(path):
        return True
    created_time = os.path.getctime(path)
    age_seconds = time.time() - created_time
    return age_seconds > max_age_days * 86400

def fetch_parsed_cache(url: str, ext: str = ".json.gz") -> Set[str]:
    """Fetch parsed data from cache for a given URL.

    Args:
        url (str): URL that was used to fetch the original data
        ext (str, optional): File extension for the cache file. Defaults to ".json.gz".

    Returns:
        Set[str]: Set of parsed data if cache exists and is not expired, None otherwise
    """
    domain = url.split("/")[2].replace(".", "_")
    subdir = f"http_{domain}" if url.startswith("http") else f"api_{domain}"
    dir_path = os.path.join(CACHE_DIR, subdir)
    key = hashlib.sha256(url.encode()).hexdigest()
    cache_path = os.path.join(dir_path, f"{key}{ext}")
    if os.path.exists(cache_path) and not is_cache_expired(cache_path):
        with gzip.open(cache_path, "rt", encoding="utf-8") as f:
            return set(json.load(f))
    return None

def store_parsed_cache(url: str, data: Set[str], ext: str = ".json.gz") -> None:
    """Store parsed data in cache for a given URL.

    Args:
        url (str): URL that was used to fetch the original data
        data (Set[str]): Set of parsed data to store
        ext (str, optional): File extension for the cache file. Defaults to ".json.gz".
    """
    domain = url.split("/")[2].replace(".", "_")
    subdir = f"http_{domain}" if url.startswith("http") else f"api_{domain}"
    dir_path = os.path.join(CACHE_DIR, subdir)
    os.makedirs(dir_path, exist_ok=True)
    key = hashlib.sha256(url.encode()).hexdigest()
    cache_path = os.path.join(dir_path, f"{key}{ext}")
    with gzip.open(cache_path, "wt", encoding="utf-8") as f:
        json.dump(list(data), f)

def fetch_archive_search_cache(query: str) -> List[Dict]:
    """Fetch Internet Archive search results from cache for a given query.

    Args:
        query (str): Search query string

    Returns:
        List[Dict]: List of search result dictionaries if cache exists and is not expired, None otherwise
    """
    domain = "api_internet_archive_org"
    dir_path = os.path.join(CACHE_DIR, domain)
    key = hashlib.sha256(query.encode()).hexdigest()
    cache_path = os.path.join(dir_path, f"{key}.json.gz")
    if os.path.exists(cache_path) and not is_cache_expired(cache_path):
        with gzip.open(cache_path, "rt", encoding="utf-8") as f:
            return json.load(f)
    return None

def store_archive_search_cache(query: str, data: List[Dict]) -> None:
    """Store Internet Archive search results in cache for a given query.

    Args:
        query (str): Search query string
        data (List[Dict]): List of search result dictionaries to store
    """
    domain = "api_internet_archive_org"
    dir_path = os.path.join(CACHE_DIR, domain)
    os.makedirs(dir_path, exist_ok=True)
    key = hashlib.sha256(query.encode()).hexdigest()
    cache_path = os.path.join(dir_path, f"{key}.json.gz")
    with gzip.open(cache_path, "wt", encoding="utf-8") as f:
        json.dump(data, f)

async def fetch_url_raw(url: str) -> str:
    """Asynchronously fetch raw HTML content from a URL with caching.

    This function attempts to fetch the content from cache first. If not found or expired,
    it makes an HTTP request to fetch the content, with up to 3 retries on failure.

    Args:
        url (str): URL to fetch

    Returns:
        str: Raw HTML content as string, or empty string if all fetch attempts fail
    """
    domain = url.split("/")[2].replace(".", "_")
    subdir = f"http_{domain}" if url.startswith("http") else f"api_{domain}"
    dir_path = os.path.join(CACHE_DIR, subdir)
    key = hashlib.sha256(url.encode()).hexdigest()
    cache_path = os.path.join(dir_path, f"{key}.html.gz")
    if os.path.exists(cache_path) and not is_cache_expired(cache_path):
        with gzip.open(cache_path, "rt", encoding="utf-8") as f:
            return f.read()
    for attempt in range(3):
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(url)
                if r.status_code == 404:
                    os.makedirs(dir_path, exist_ok=True)
                    with gzip.open(cache_path, "wt", encoding="utf-8") as f:
                        f.write("")
                    return ""
                r.raise_for_status()
                os.makedirs(dir_path, exist_ok=True)
                with gzip.open(cache_path, "wt", encoding="utf-8") as f:
                    f.write(r.text)
                return r.text
        except Exception as e:
            print(f"[cache] Attempt {attempt+1} failed for {url}: {e}")
            await asyncio.sleep(1)
    return ""

async def fetch_and_parse_filenames(url: str) -> Set[str]:
    """Asynchronously fetch HTML content from a URL and parse it to extract package filenames.

    Args:
        url (str): URL to fetch and parse

    Returns:
        Set[str]: Set of cleaned package filenames extracted from the HTML
    """
    html = await fetch_url_raw(url)
    if not html:
        return set()
    soup = BeautifulSoup(html, "html.parser")
    return {
        clean_filename(a.text)
        for a in soup.find_all("a", href=True)
        if ".pkg.tar" in a.text and not a.text.endswith(".sig")
    }

async def fetch_archlinux_org_filenames(pkg_name: str) -> Set[str]:
    """Asynchronously fetch package filenames from archive.archlinux.org for a given package.

    Args:
        pkg_name (str): Package name to fetch filenames for

    Returns:
        Set[str]: Set of cleaned package filenames
    """
    base = pkg_name.replace("archlinux_pkg_", "")
    url = f"https://archive.archlinux.org/packages/{base[0]}/{quote(base)}/"
    cached = fetch_parsed_cache(url)
    if cached is not None:
        return cached
    parsed = await fetch_and_parse_filenames(url)
    store_parsed_cache(url, parsed)
    return parsed

async def fetch_archive_org_filenames(pkg_name: str) -> Set[str]:
    """Asynchronously fetch package filenames from archive.org for a given package.

    Args:
        pkg_name (str): Package name to fetch filenames for

    Returns:
        Set[str]: Set of cleaned package filenames
    """
    url = f"https://archive.org/download/{pkg_name}/"
    cached = fetch_parsed_cache(url)
    if cached is not None:
        return cached
    parsed = await fetch_and_parse_filenames(url)
    store_parsed_cache(url, parsed)
    return parsed

def get_filename_versions(filename: str) -> Dict[str, Set[str]]:
    """Get version information for a given filename from package repositories.

    This is the main entry point for the module. It searches for packages matching
    the given filename in both archive.org and archive.archlinux.org, and returns
    a dictionary mapping package names to sets of version strings. Package names
    with empty sets of versions are discarded from the result.

    Args:
        filename (str): Filename to search for

    Returns:
        Dict[str, Set[str]]: Dictionary mapping package names to sets of version strings,
            excluding any packages with empty version sets
    """
    async def _get():
        query = 'subject:"archlinux package" AND subject:' + filename
        cached = fetch_archive_search_cache(query)
        if cached is not None:
            results = cached
        else:
            session = ArchiveSession()
            for attempt in range(3):
                try:
                    search = Search(session, query)
                    results = list(search)
                    store_archive_search_cache(query, results)
                    break
                except Exception as e:
                    print(f"[search] retry {attempt+1} failed: {e}")
                    await asyncio.sleep(1)
            else:
                return {}
        tasks = []
        for result in results:
            identifier = result["identifier"]
            tasks.append(fetch_archive_org_filenames(identifier))
            tasks.append(fetch_archlinux_org_filenames(identifier))
        fetch_results = await atqdm.gather(*tasks)
        version_map: Dict[str, Set[str]] = {}
        i = 0
        for result in results:
            raw_identifier = result["identifier"]
            identifier = raw_identifier.replace("archlinux_pkg_", "").lower()
            variants = generate_prefix_variants(identifier)
            versions = set()
            for r in fetch_results[i:i+2]:
                versions.update(r)
            i += 2
            cleaned = set()
            for v in versions:
                matched = False
                for variant in variants:
                    if v.startswith(variant):
                        stripped = v[len(variant):]
                        if stripped.startswith("-"):
                            stripped = stripped[1:]
                        cleaned.add(re.sub(r"[^a-zA-Z0-9]+", ".", stripped))
                        matched = True
                        break
                if not matched:
                    cleaned.add(re.sub(r"[^a-zA-Z0-9]+", ".", v))
            if cleaned:  # Only add to version_map if the set of versions is not empty
                version_map[identifier] = cleaned
        return version_map
    return asyncio.run(_get())

# for debugging only
def print_filename_versions(version_map: Dict[str, Set[str]]) -> None:
    """Print package names and their versions in a readable format.

    This function is for debugging purposes only.

    Args:
        version_map (Dict[str, Set[str]]): Dictionary mapping package names to sets of version strings
    """
    for name, versions in version_map.items():
        print(f"{name}:{', '.join(sorted(versions))}")
