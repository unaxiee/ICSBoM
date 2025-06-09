import re
from Levenshtein import ratio
from util.package_repo_scraper import get_filename_versions
from util.PackageDB import PackageDB
from util import config

# Persistent PackageDB instance for reuse
_package_db = None


# Similarity between two x.y.z versions
def version_distance(ver_a: str, ver_b: str) -> int:
    """Similarity between two x.y[.z] versions.

    Args:
        ver_a (str): Version string in "x.y[.z]" format. E.g: "1.2", "1.2.3"
        ver_b (str): Version string in "x.y[.z]" format. E.g: "1.2", "1.2.3"

    Returns:
        int: Integer distance
    """

    # Parse version numbers
    res_a = re.search(r"(\d+)\.(\d+)(\.(\d+))*", ver_a)
    res_b = re.search(r"(\d+)\.(\d+)(\.(\d+))*", ver_b)
    version_a = {'major': int(res_a.group(1)), 'minor': int(res_a.group(2)), 'patch': int(res_a.group(4)) if res_a.group(4) else 0}
    version_b = {'major': int(res_b.group(1)), 'minor': int(res_b.group(2)), 'patch': int(res_b.group(4)) if res_b.group(4) else 0}

    return 10000 * abs(version_a['major'] - version_b['major']) + 100 * abs(version_a['minor'] - version_b['minor']) + abs(version_a['patch'] - version_b['patch'])


# Resolve version number using AUR archive and internet archive sources
def version_res_arch_local(filename: str, candidate_versions: list[str]) -> str:
    """Given a filename and a list of candidate version strings in "x.y.z" format, 
    this function uses package_repo_scraper to get versions for the most likely 
    version string candidate.
    This helps in the event that we have multiple candidate version strings when 
    inspecting a binary's strings

    Args:
        filename (str): Binary or library file name.
        candidate_versions (list[str]): List of candidate string versions in "x.y.z" format

    Returns:
        str: Closest candidate string.
    """

    # Remove anything trailing .so
    if '.so' in filename:
        filename = re.sub(r"\.so.*", ".so", filename)

    # Final result dictionary
    final_version = {
        'version': None,
        'distance': 39000 # This acts as a distance threshold
    }

    # Progressively abstract filename to generalize query
    filenames = {filename, filename.split('.so')[0], filename.split('.so')[0].split('-')[0]}

    # Iterate over possible queries
    for filename in filenames:
        # Get versions using package_repo_scraper
        version_map = get_filename_versions(filename)

        # If no results, skip this filename
        if not version_map:
            continue

        # Iterate over packages in the results
        for _, versions in version_map.items():
            for match_version in versions:
                if not re.search(r"(\d+(\.\d+){1,2})", match_version):
                    continue
                # Distances dictionary list
                cand_dicts = []
                # Iterate over candidate versions and calculate distance
                for cand_version in candidate_versions:
                    cand_dicts.append({'version': cand_version, 'distance': version_distance(cand_version, match_version)})
                # Sort dictionary by distance
                sorted_candidates_list = sorted(cand_dicts, key=lambda c: c['distance'])
                # Keep best match if lower than current final result
                if final_version['distance'] > sorted_candidates_list[0]['distance']:
                    final_version = {
                        'version': sorted_candidates_list[0]['version'],
                        'distance': sorted_candidates_list[0]['distance']
                    }

    return str(final_version['version'])


def match_binary_to_package(p_query_name: str, package_db=None):
    if package_db is None:
        global _package_db
        if _package_db is None:
            _package_db = PackageDB(
                urls=config.PACKAGE_DB_URLS,
                local_paths=config.PACKAGE_DB_LOCAL_PATHS,
                cache_dir=config.PACKAGE_DB_CACHE_DIR
            )
        package_db = _package_db

    # Search for filenames containing the query name
    matching_filenames = package_db.search_substring(p_query_name)

    # If there are no results, skip this binary
    if not matching_filenames:
        return None

    # Get package names for each matching filename
    p_matches = []
    for filename in matching_filenames:
        package_name = package_db.lookup_exact(filename)
        if package_name:
            p_matches.append({"NAME": package_name})

    # If there are no package matches, return None
    if not p_matches:
        return None

    # Sort matches by ascending Levenshtein string distance (package name, binary name)
    p_matches.sort(key=lambda x: ratio(x["NAME"], p_query_name))

    # Return package name of package with highest Levenshtein similarity to binary
    return p_matches[-1]["NAME"]

# Resolve version number using AUR sources
# def version_res_arch(filename: str, candidate_versions: list[str], session=None) -> str:
#     """Given a filename and a list of candidate version strings in "x.y.z" format, 
#     this function queries the AUR for the most likely version string candidate.
#     This helps in the event that we have multiple candidate version strings when 
#     inspecting a binary's strings

#     Args:
#         filename (str): Binary or library file name.
#         candidate_versions (list[str]): List of candidate string versions in "x.y.z" format
#         session (optional): Optional requests session object to speed things up.

#     Returns:
#         str: Closest candidate string.
#     """

#     # If no requests session is provided, create one
#     if not session:
#         session = requests.Session()

#     # Arch repo URL
#     query_addr = "https://archlinux.org/packages/search/json/?q={}"

#     # Remove anything trailing .so
#     if '.so' in filename:
#         filename = re.sub(r"\.so.*", ".so", filename)

#     # Final result dictionary
#     final_version = {
#         'version': None,
#         'distance': 39000 # This acts as a distance threshold
#     }

#     # Progressively abstract filename to generalize query
#     filenames = set([filename, filename.split('.so')[0], filename.split('.so')[0].split('-')[0]])

#     # Iterate over possible queries
#     for filename in filenames:

#         # Query the Arch repositories API for similar packages
#         req_json = session.get(query_addr.format(filename), headers=config.REQ_HEADERS).json()

#         # Check if results exist. If not, move on to the next strategy
#         if not req_json["results"]:
#             continue
#         else:

#             # Iterate over packages in the query results
#             for query_package in req_json["results"]:
#                 # Get the match package version
#                 match_version = query_package["pkgver"]
#                 # TODO: Skip versions not in the x.y[.z] format for now
#                 if not re.search(r"(\d+(\.\d+){1,2})", match_version):
#                     continue

#                 # Distances dictionary list
#                 cand_dicts = []

#                 # Iterate over candidate versions and calculate distance
#                 for cand_version in candidate_versions:
#                     cand_dicts.append({'version': cand_version, 'distance': version_distance(cand_version, match_version)})

#                 # Sort dictionary by distance
#                 sorted_candidates_list = sorted(cand_dicts, key=lambda c: c['distance'])
#                 # print(sorted_candidates_list)

#                 # Keep best match if lower than current final result
#                 if final_version['distance'] > sorted_candidates_list[0]['distance']:
#                     final_version = {
#                         'version': sorted_candidates_list[0]['version'],
#                         'distance': sorted_candidates_list[0]['distance']
#                     }

#     return final_version['version']
