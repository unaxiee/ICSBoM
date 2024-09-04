1. Firmware Pre-processing & TPC and Version Identification
Run 'STEP0_firmware_preprocessing.py' to extract firmware files, collect file metadata, and identify TPCs as well as their versions.

2. CVE Database Lookup
Run 'STEP1_vulnerability_searching.py' to collect all vulnerabilities associated with given TPCs of specific versions.

3. Target Function Locating
Run 'STEP2_function_locating.py' to normalize assembly instructions, generate fuzzy hash values for functions and crypto hash values for basic blocks contained in each function, and locate target functions in firmware-extracted stripped binaries.
Results are stored in 'output_function_locating/'.

4. Security Patch Detection
Run 'STEP3_patch_detection.py' to determine if each vulnerability exists or the security patch has been backported.
Results are stored in 'output_patch_detection/'.

All input arguments can be modified in 'util/config.py'. Step 1 requires firmware name and path. Steps 2 through 4 require vendor name, and all scripts take in corresponding csv file in 'util/fw_lib_list' as input.

All firmware-extracted target binaries and built reference binaries can be found in https://drive.google.com/file/d/1vQ5dv9CgVoh28GbZjrylH3WNVPzY_WHF/view?usp=sharing
