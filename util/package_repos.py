import re
from pymongo import MongoClient
from Levenshtein import ratio


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


# Resolve version number using AUR sources
def version_res_arch_local(filename: str, candidate_versions: list[str]) -> str:
    """Given a filename and a list of candidate version strings in "x.y.z" format, 
    this function queries the local Arch repositories database for the most likely 
    version string candidate.
    This helps in the event that we have multiple candidate version strings when 
    inspecting a binary's strings

    Args:
        filename (str): Binary or library file name.
        candidate_versions (list[str]): List of candidate string versions in "x.y.z" format
        session (optional): Optional requests session object to speed things up.

    Returns:
        str: Closest candidate string.
    """

    # MongoDB client, database and collections
    db_client = MongoClient('localhost', 27017)
    pack_db = db_client['arch_armv7']
    coll_core = pack_db['core']
    coll_extra = pack_db['extra']

    # Remove anything trailing .so
    if '.so' in filename:
        filename = re.sub(r"\.so.*", ".so", filename)

    # Final result dictionary
    final_version = {
        'version': None,
        'distance': 39000 # This acts as a distance threshold
    }

    # Progressively abstract filename to generalize query
    filenames = set([filename, filename.split('.so')[0], filename.split('.so')[0].split('-')[0]])
    
    # Iterate over possible queries
    for filename in filenames:
        # Form query
        p_query = {
            'NAME': {
                '$regex': f'.*{filename}.*',
            }
        }

        # Query the core database first. If there are no matches, then check the extra repository
        p_matches = [match for match in coll_core.find(p_query, {'NAME': 1, 'VERSION': 1, '_id': 0})]
        if len(p_matches) == 0:
            p_matches = [match for match in coll_extra.find(p_query, {'NAME': 1, 'VERSION': 1, '_id': 0})]
            # If there are still no results, skip this filename
            if len(p_matches) == 0:
                continue

        # Iterate over packages in the query results
        for query_package in p_matches:
            # Get the match package version
            match_version = query_package["VERSION"]
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

    return final_version['version']


def match_binary_to_package(p_query_name:str):

    # MongoDB client, database and collections
    db_client = MongoClient('localhost', 27017)
    pack_db = db_client['arch_armv7']
    coll_core = pack_db['core']
    coll_extra = pack_db['extra']

    # Form query for finding file in packages DB
    p_query = {
        'FILES': {
            '$in': [
                re.compile(f'.*/{p_query_name}[^/]*')
            ]
        }
    }
    
    # Choose fields to return
    p_queryf = {'NAME': 1, '_id': 0}

    # Get matches
    # Query the core database first. If there are no matches, then check the extra repository
    p_matches = [match for match in coll_core.find(p_query, p_queryf)]
    p_matches.extend([match for match in coll_extra.find(p_query, p_queryf)])

    # If there are no results, skip this binary
    if len(p_matches) == 0:
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