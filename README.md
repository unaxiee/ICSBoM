Firmware Pre-processing
1. Run 'preprocess.py' to extract all files from given firmware, collect file metadata, and identify TPCs as well as their versions.

Target Function Locating
1. Run 'disasm/parse_hash.py' to generate fuzzy as well as crypto hash values for assembly. The inputs are from 'disasm/disasm_raw' and outputs are stored in 'disasm/disasm_hash'.
2. Run 'locate.py' to locate target functions in target binary given reference binary and results are stored in 'output_function_locating'.

Security Patch Detection
1. Run 'disasm/parse_disasm.py' to normalize assembly. The inputs are from 'disasm/disasm_raw' and outputs are stored in 'disasm/disasm_norm'.
2. Run 'detect.py' to detect security patches by comparing the triplet of target, vulnerabvle, and patched functions and results are stored in 'output_patch_detection'.

All input arguments can be adjusted in 'util/config.py'

All extracted executable files from firmware and reference TPCs can be found in https://drive.google.com/file/d/1nxyFCAq7pmhsuFnH_JHPQZFZPDuo6BJK/view?usp=drive_link
