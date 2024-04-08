import re


# Binary mime signatures. We use these to filter the extracted files
bin_mime_signs = set(["application/x-executable", "application/x-pie-executable", "application/x-sharedlib"])
# Complete mime types
com_mime_types = set(['application/octet-stream', 'application/x-pie-executable', 'application/x-xz', 'application/x-sharedlib', 'application/x-terminfo', 'application/json', 'application/x-bzip2', 'application/x-executable', 'application/vnd.ms-fontobject', 'application/x-terminfo2', 'application/x-object',
                      'text/x-c', 'text/plain', 'text/x-php', 'text/xml', 'text/csv', 'text/x-java', 'text/x-perl', 'text/x-script.python', 'text/x-shellscript', 'text/html',
                      'font/sfnt',
                      'image/svg+xml',  'image/png'])

# Names of GNU Coreutils. We can't easily find strings on these, so skip them
coreutils_names = set(["arch", "base64", "basename", "cat", "chcon", "chgrp", "chmod", "chown", "chroot", 
                       "cksum", "comm", "cp", "csplit", "cut", "date", "dd", "df", "dir", "dircolors", 
                       "dirname", "du", "echo", "env", "expand", "expr", "factor", "false", "fmt", 
                       "fold", "groups", "head", "hostid", "hostname", "id", "install", "join", "kill", 
                       "link", "ln", "logname", "ls", "md5sum", "mkdir", "mkfifo", "mknod", "mktemp", 
                       "mv", "nice", "nl", "nohup", "nproc", "numfmt", "od", "paste", "pathchk", "pinky", 
                       "pr", "printenv", "printf", "ptx", "pwd", "readlink", "realpath", "rm", "rmdir", 
                       "runcon", "seq", "shred", "shuf", "sleep", "sort", "split", "stat", "stdbuf", 
                       "stty", "sum", "tac", "tail", "tee", "test", "timeout", "touch", "tr", "true", 
                       "truncate", "tsort", "tty", "uname", "unexpand", "uniq", "unlink", "uptime", 
                       "users", "vdir", "wc", "who", "whoami", "yes"])


# ========= VERSION STRING SIGNATURES =========
# Header signatures to remove when working with version identification heuristics
header_regexes = [r"GLIBC_[\d\.]+", r"ZLIB_[\d\.]+", r"CXXABI_[\d\.]+", r"CXXABI_ARM_[\d\.]+", r"LIBXML2_[\d\.]+"]

# Binary version signatures
bin_indirect_version = {
    'openssl': {
        'version': r"OpenSSL (\d\.\d\.\d[a-z]{0,2})",
        'build_date': r"OpenSSL \d\.\d\.\d[a-z]{0,2}\s+(\d+\s[A-Za-z]{3}\s\d{4})"
    },
    'libssl': {
        'version': r"OpenSSL (\d\.\d\.\d[a-z]{0,2})",
        'build_date': r"OpenSSL \d\.\d\.\d[a-z]{0,2}\s+(\d+\s[A-Za-z]{3}\s\d{4})"
    },
    'libcrypto': {
        'version': r"OpenSSL (\d\.\d\.\d[a-z]{0,2})",
        'build_date': r"OpenSSL \d\.\d\.\d[a-z]{0,2}\s+(\d+\s[A-Za-z]{3}\s\d{4})"
    },
    # Advanced Intrusion Detection Environment
    'aide': {
        'version': r"Aide (\d+\.\d+\.\d+)",
    },
    'bash': {
        'version': r"version (\d\.\d+\.\d+\(\d+\))",
    },
    'opkg': {
        'version': r"opkg version (\d+\.\d+\.\d+)",
    },
    'curl': {
        'version': r"curl (\d+\.\d+\.\d+)",
    },
    'htop': {
        'version': r"htop (\d+\.\d+\.\d+)",
    },
    'find': {
        'version': r"(\d+\.\d+\.\d+)",
    },
    'fusermount3': {
        'version': r"(\d+\.\d+\.\d+)",
    },
    'iperf': {
        'version': r"iperf version (\d+\.\d+\.\d+)",
        'build_date': r"iperf version \d+\.\d+\.\d+ \((\d+\s[A-Za-z]{3}\s\d+)\)",
    },
    'lowntfs-3g': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'lsuio': {
        'version': r"libuio\s(\d+\.\d+\.\d+)",
    },
    'mdmd': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'mosquitto_pub': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'mosquitto_sub': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'nano': {
        'version': r"nano\s+(\d+\.\d+\.\d+)",
    },
    'ntfs-3g': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'opcua-server': {
        'version': r"\n(\d+\.\d\.\d+)\n",
        'sdk_version': r"opcuacsdk-(\d+\.\d+\.\d+)",
    },
    'php7': {
        'version': r"PHP/(\d+\.\d+\.\d+)\n",
    },
    'pki': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'ps': {
        'version': r"procps-ng\s+(\d+\.\d+\.\d+)",
    },
    'pv': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'spawn-fcgi': {
        'version': r"spawn-fcgi\s+v(\d+\.\d+\.\d+)"
    },
    'top': {
        'version': r"procps-ng\s+(\d+\.\d+\.\d+)",
    },
    'libarchive': {
        'version': r"libarchive\s+(\d+\.\d+\.\d+)",
    },
    'libblkid': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'libboost': {
        'version': r"libboost_.*\.so\.(\d+\.\d+\.\d+)",
    },
    'libbz2': {
        'version': r"\n(\d+\.\d+\.\d+)",
        'release_date': r"\n\d+\.\d+\.\d+,\s+(\d+-[A-Za-z]*-\d+)"
    },
    'libc': {
        'version': r"release version (\d\.\d+)",
    },
    'libcares': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'libcurl': {
        'version': r"libcurl/(\d+\.\d+\.\d+)",
    },
    'libdbus': {
        'version': r"libdbus\s(\d+\.\d+\.\d+)",
    },
    'libebtc': {
        'version': r"ebtables\s(\d+\.\d+\.\d+-\d+)",
    },
    'libexpat': {
        'version': r"expat_(\d+\.\d+\.\d+)",
    },
    'libext2fs': {
        'version': r"EXT2FS Library version (\d+\.\d+\.\d+)",
    },
    'libfdisk': {
        'version': r"(\d+\.\d+\.\d+)",
    },
    'libfdisk': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'libfuse': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'libgcrypt': {
        'version': r"Libgcrypt\s(\d+\.\d+\.\d+)",
    },
    'libglib': {
        'version': r"glib-(\d+\.\d+\.\d+)",
    },
    'libgobject': {
        'version': r"glib-(\d+\.\d+\.\d+)",
    },
    'liblzma': {
        'version': r"\n(\d+\.\d+\.\d+)",
    },
    'libModbus': {
        'version': r"libModbus-(\d+\.\d+\.\d+)",
    },
    'libmodbus': {
        'version': r"LMB(\d+\.\d+\.\d+)"
    },
    'libncurses': {
        'version': r"ncurses\s(\d+\.\d+\.\d+)",
    },
    'libnetsnmp': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'libnet': {
        'version': r"libnet version (\d+\.\d+\.\d+)",
    },
    'libpcap': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'libprotobuf-lite': {
        'version': r"libprotobuf-lite.so.(\d+\.\d+\.\d+)",
    },
    'libsmartcols': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'libsqlite3': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'libsyslog-ng': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'libtirpc': {
        'version': r"TIRPC_(\d+\.\d+\.\d+)", # NOTE: Get the last of multiple results
    },
    # OPC UA
    'libuastack': {
        'version': r"Version:(\d+\.\d+\.\d+)",
    },
    'libxml2': {
        'version': r"LIBXML2_(\d+\.\d+\.\d+)", # NOTE: Get the biggest version number of multiple results
    },
    'libxslt': {
        'version': r"LIBXML2_(\d+\.\d+\.\d+)", # NOTE: Get the biggest version number of multiple results
    },
    'libz': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'mod_deflate': {
        'version': r"\n(\d+\.\d+\.\d+)\n", # lighttpd
    },
    'busybox': {
        'version': r"BusyBox\sv(\d+\.\d+\.\d+)",
    },
    'candump': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'canecho': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'cansend': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'codesys3': {
        'version': r"\n(3\.\d+\.\d+\.\d+)\n",
    },
    'dbus-': {
        'version': [r"\n(\d+\.\d+\.\d+)\n", r"LIBDBUS_PRIVATE_(\d+\.\d+\.\d+)"],
    },
    'dumpkeys': {
        'version': r"kbd\s(\d+\.\d+\.\d+)",
    },
    'getkeycodes': {
        'version': r"kbd\s(\d+\.\d+\.\d+)",
    },
    'loadkeys': {
        'version': r"kbd\s(\d+\.\d+\.\d+)",
    },
    'figlet': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'gdisk': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'lscgroup': {
        'version': r"CGROUP_(\d+\.\d+\.\d+)",
    },
    'lssubsys': {
        'version': r"CGROUP_(\d+\.\d+\.\d+)",
    },
    'ltrace': {
        'version': r"ltrace version (\d+\.\d+\.\d+)",
    },
    'nl-': {
        'version': r"libnl\s(\d+\.\d+\.\d+)"
    },
    'sgdisk': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'ssh': {
        'version': r"OpenSSH_(\d+\.\d+\.\d+)"
    },
    'stress': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'sudo': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'unzip': {
        'version': r"(\d+\.\d+\.\d+)\s\d+",
        'date': r"\d+\.\d+\.\d+\s(\d{6,8})",
    },
    'libbacnet': {
        'version': r"\n(\d+\.\d+\.\d+)\n",
    },
    'libcgroup': {
        'version': r"CGROUP_(\d+\.\d+\.\d+)",
    },
    'libcifX': {
        'version': r"cifX Toolkit (\d+\.\d+\.\d+\.\d+)"
    },
    'libfreetype': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'libglib': {
        'version': r"glib-(\d+\.\d+\.\d+)"
    },
    'libgmp': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'libjansson': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'libjpeg': {
        'version': r"version\s(\d+\.\d+\.\d+)"
    },
    'libnl-cli': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'libnsl': {
        'version': r"LIBNSL_(\d+\.\d+\.\d+)" # Use the largest result
    },
    'liboil': {
        'version': r"liboil-(\d+\.\d+\.\d+)"
    },
    'libnsl': {
        'version': r"LIBPAM_MODUTIL_(\d+\.\d+\.\d+)" # Use the largest result
    },
    'libpng': {
        'version': r"libpng\sversion\s(\d+\.\d+\.\d+)"
    },
    'libpython': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'libsmartcols': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'libssh2': {
        'version': r"SSH-2.0-libssh2_(\d+\.\d+\.\d+)"
    },
    'libTscIoDrv': {
        'version': r"Rev.*(\d+\.\d+\.\d+\.\d+)"
    },
    'blkid': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'canconfig': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'candemo': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'cgconfigparser': {
        'version': r"CGROUP_(\d+\.\d+\.\d+)",
    },
    'e2fsck': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'e2label': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'flash': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'ftl': {
        'version': r"\n(\d+\.\d+\.\d+)\n"
    },
    'ipsec': {
        'version': r"IPSEC_VERSION=.*(\d+\.\d+\.\d+)"
    },
    'ipwatchd': {
        'version': r"IPwatchD\s(\d+\.\d+\.\d+)"
    },
    'jffs2dump': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'lighttpd': {
        'version': r"lighttpd/(\d+\.\d+\.\d+)"
    },
    'logrotate': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'mke2fs': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'mkfs': {
        'version': r"\n(\d+\.\d+\.\d+)" # Get first result
    },
    'mount.nfs': {
        'version': r"nfs-utils\s(\d+\.\d+\.\d+)"
    },
    'mtdinfo': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'nfsstat': {
        'version': r"nfsstat:\s(\d+\.\d+\.\d+)"
    },
    'openvpn': {
        'version': r"OpenVPN\s(\d+\.\d+\.\d+)"
    },
    'pure-ftpd': {
        'version': r"pure-ftpd\sv\s(\d+\.\d+\.\d+)"
    },
    'resize2fs': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'rpc.statd': {
        'version': r"version\s(\d+\.\d+\.\d+)"
    },
    'showmount': {
        'version': r"showmount for (\d+\.\d+\.\d+)"
    },
    'sm-notify': {
        'version': r"Version (\d+\.\d+\.\d+)"
    },
    'tcpdump': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'tune2fs': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'ubi': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'unsquashfs': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
    'xtables-legacy-multi': {
        'version': r"\n(\d+\.\d+\.\d+)"
    },
}

bin_direct_version = ['libxml2']