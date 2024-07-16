# Firmware file to process
FW_NAME = 'PFC100-22-10-1x.img'

# Directory containing the firmware file
FW_DIR = '../wago/firmware'
# FW_DIR = '../siemens/firmware'
# FW_DIR = '../firmware/Mitsubishi'

# Binwalk log name
BW_LOG_NAME = "binwalk_log.txt"

# Binwalk recursive extraction depth
BW_DEPTH = 8

ven = 'wago'
fw = ''
fw_ver = ''
lib = ''
lib_ver = ''
lib_name = ''

test_lib = 'libarchive'
test_fw_ver = '26'
