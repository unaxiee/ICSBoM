# For STEP0
# Firmware file to process
FW_NAME = 'PDU.img'

# Directory containing the firmware file
# FW_DIR = '../wago/firmware'
# FW_DIR = '../siemens/firmware'
FW_DIR = '../firmware/Eaton'

# Binwalk log name
BW_LOG_NAME = "binwalk_log.txt"

# Binwalk recursive extraction depth
BW_DEPTH = 8

# For STEP1 through STEP3
# Vendor name
ven = 'yocto'
# Firmware name
fw = ''
# Firmware version
fw_ver = ''
# TPC name
lib = ''
# TPC version
lib_ver = ''
# Binary name
lib_name = ''

# For test of specific combination of firmware and TPC
# Test TPC name
test_lib = 'openssl'
# Test firmware version (fixed vendor)
test_fw_ver = ''
# Test compiler
test_compiler = ''
