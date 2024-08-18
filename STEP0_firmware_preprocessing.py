from util import config
import os
from util.binwalk import binwalk_unpack_fw
from glob import glob
from tqdm import tqdm
import magic
from util.binary_signatures import bin_mime_signs, bin_direct_version, bin_indirect_version, header_regexes
import subprocess
import re
from util.package_repos import version_res_arch_local, match_binary_to_package
import pickle


# ======== Step 1: Unpack firmware ========
print(f"[i] Step 1: Processing firmware: {config.FW_DIR}/{config.FW_NAME}")
extract_fw = True
OUT_DIR = f"firmware_out_{config.FW_NAME.rsplit('.', 1)[0]}"
if os.path.isdir(f"{config.FW_DIR}/{OUT_DIR}"):
    print(f"[i] Extracted firmware directory found: {OUT_DIR}. Using this.")
    extract_fw = False
else:
    os.mkdir(f'{config.FW_DIR}/{OUT_DIR}')
# If firmware needs to be extracted, use binwalk
if extract_fw:
    print("[i] Extracting firmware using binwalk. This might take a few minutes.")
    bw_status = binwalk_unpack_fw(
        firmware=config.FW_NAME,
        fw_dir=config.FW_DIR,
        out_dir=OUT_DIR,
        log_file=config.BW_LOG_NAME,
        bw_depth=config.BW_DEPTH)
    print("[i] Firmware extraction finished.")
    if bw_status != 0:
        print("[e] Error unpacking firmware with binwalk. Exiting.")
        exit(1)
else:
    print("[i] Using pre-extracted firmware")


# ======== Step 2: Discover files ========
print("[i] Step 2: Locating and calculating metadata for binaries of interest.")
paths = glob(f"{config.FW_DIR}/{OUT_DIR}/**", recursive=True)
print(f"[i] Scanning {len(paths)} files and directories.")
binaries = []
for path in tqdm(paths):
    if os.path.isdir(path):
        continue
    # Check if file has executable mime type
    try:
        if magic.from_file(path, mime=True) in bin_mime_signs:
            file_metadata = dict()
            file_metadata['path'] = path
            file_metadata['name'] = path.split('/')[-1]
            binaries.append(file_metadata)
    except:
        print(f"[e] Reading {path} fails.")
        continue
print(f"[i] Found {len(binaries)} executable files.")
if len(binaries) == 0:
    print("[i] Exiting.")
    exit(1)


# ==== Step 3: Identify binary versions using regex signatures ====
print("[i] Step 3: Running signature based version identification.")
found_sign_counter = 0
for binary in tqdm(binaries):
    bin_name = binary["name"]
    match_flag = False
    # Special match case: version can be found in binary name
    for sig_name in bin_direct_version:
        if sig_name in bin_name:
            version = bin_name.split('so.')[-1]
            binary["version"] = version
            binary["version_id_method"] = "signature"
            found_sign_counter+=1
            match_flag = True
            break
    if match_flag:
        continue
    # Iterate over filename patterns and see if they match the binary name
    for bin_key, bin_dict in bin_indirect_version.items():
        # Get name pattern
        if 'lib' in bin_key:
            pattern = f"^{bin_key}.*\.so.*"
        else:
            pattern = f"^{bin_key}$"
        # Check if pattern matches the binary name, and try to identify the version
        if re.search(pattern, bin_name):
            binary_str = subprocess.run(["strings", binary["path"]], capture_output=True).stdout
            version = re.search(str.encode(bin_dict['version']), binary_str)
            if version:
                version = version.group(1).decode("utf-8")
                binary["version"] = version
                binary["version_id_method"] = "signature"
                found_sign_counter+=1
                match_flag = True
                break
print(f"[i] Located {found_sign_counter} versions using signatures.")


# ==== Step 4: Identify binary versions using repo resolution ====
print(f"[i] Step 4: Identifying packages using pattern hinting and repository resolution.")
print("[i] Using local DB-backed resolution for speed. Switch to online method for potentially better accuracy.")
found_repo_counter = 0
found_rand_counter = 0
for binary in tqdm(binaries):
    if "version" in binary.keys():
        continue
    bin_name = binary["name"]
    # Use generic pattern hint to capture both x.y and x.y.z version numbers
    pattern_hint = r"(\d+(\.\d+){1,2})"
    # Get all candidate version strings from binary using pattern hint
    with open(binary["path"], 'rb') as fp:
        binary_str = fp.read()
    # Suppress known header patterns that yield false positives
    for header_pattern in header_regexes:
        binary_str = re.sub(str.encode(header_pattern), b'', binary_str)
    cand_versions = set(re.findall(str.encode(pattern_hint), binary_str))
    if not cand_versions:
        continue
    # Decode binary strings
    cand_versions = [v[0].decode("utf-8") for v in cand_versions]

    # Get final version by using repository resolution heuristics
    # version = version_res_arch(bin_name, cand_versions, session)

    # Swapped out the above for the local db-backed version of the function
    version = version_res_arch_local(bin_name, cand_versions)
    # If a version is not found, but we have candidates, pick one at random
    if not version:
        binary["version"] = cand_versions[-1]
        binary["version_id_method"] = "random_candidate"
        found_rand_counter += 1
    else:
        binary["version"] = version
        binary["version_id_method"] = "repo_resolution"
        found_repo_counter += 1
print(f"[i] Located {found_repo_counter} versions using repository resolution.")
print(f"[i] Stochastically selected {found_rand_counter} versions from candidates.")


# ==== Step 5: Match files to packages ====
"""
A package can have multiple files belonging to it. For instance, OpenSSL has openssl, libcrypto, and libssl.
We need a file -> package dictionary. Once we know which packages are present in the FW we can use this to 
find which packages need to be built and added to the databases.

Future to-do: we can download the arch repository data files. Import them into our database, and query offline 
to improve speed.
https://wiki.archlinux.org/title/Mirrors
https://mirror.csclub.uwaterloo.ca/archlinux/
ARM: http://gr.mirror.archlinuxarm.org/armv7h/
Just download the core.db.tar.gz and core.files.tar.gz. These are easily parsable using regex.

Steps: 
    1. Reverse search the Arch and Debian repositories to get files corresponding to packages
    2. Get packages and their metadata along with git repository URLs and version tags

"""
print("[i] Step 5: Matching binaries to packages.")
bin_packages = set()
for binary in tqdm(binaries):
    if not "version" in binary.keys():
        continue
    # Form query for finding file in packages DB
    p_query_name = re.escape(binary["name"])
    # Get matches by querying DB
    pkg_name = match_binary_to_package(p_query_name)
    if pkg_name:
        # Assign package name of package with highest Levenshtein similarity to binary
        binary["package_name"] = pkg_name
        # Add package to set of packages that we need to investigate
        bin_packages.update({pkg_name})


# Save temporary results
with open(f"util/fw_pkl/{config.FW_NAME.rsplit('.', 1)[0]}.pkl", 'wb') as f:
    pickle.dump(binaries, f)
