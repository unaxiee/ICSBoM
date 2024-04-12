from pymongo import MongoClient
import csv
from packaging import version
import sys
sys.path.append('/media/yongyu/Data/ICS/FSS')
from util import config

client = MongoClient('localhost', 27017)
db = client['lib_vul_db']

# statistics
def calculate_statistics(lib):
    collection = db[lib]
    cve = set()
    fix_ver = set()
    func_name = set()
    for doc in collection.find():
        cve.add(doc['CVE'])
        fix_ver.add(doc['fixed_version'])
        if 'function_name' in doc.keys():
            for func in doc['function_name']:
                func_name.add(func)
    print(len(cve), cve)
    print(len(fix_ver), fix_ver)
    print(len(func_name), func_name)

# per package version (list)
def generate_func_list_for_list_per_package(lib, lib_ver, fw_ver):
    if lib == 'openssl':
        collection = db[lib + '_' + lib_ver[:-1]]
    else:
        collection = db[lib]
    build_version = {lib_ver}
    # for different openssl series
    with open('func_list_' + ven + '/' + lib + '_' + fw_ver + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'affected_since_version' in doc.keys():
                if lib != 'openssl' and version.parse(lib_ver) < version.parse(doc['affected_since_version']):
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue
                elif lib == 'openssl' and lib_ver < doc['affected_since_version']:
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue

            if lib != 'openssl' and version.parse(lib_ver) >= version.parse(doc['fixed_version']):
                print('skip', doc['CVE'], '(fixed in', doc['fixed_version'], ')')
                continue
            elif lib == 'openssl' and lib_ver >= doc['fixed_version']:
                print('skip', doc['CVE'], '(fixed in', doc['fixed_version'], ')')
                continue
            
            if 'function_name' not in doc.keys():
                print('error', doc['CVE'], 'has no function name')
            else:
                cnt = 0
                if 'update_function_name' in doc.keys():
                    for update_func in doc['update_function_name']:
                        cnt += 1
                        print(doc['CVE'], doc['fixed_version'], update_func)
                        wr.writerow([doc['CVE'], doc['fixed_version'], update_func])
                else:
                    for func in doc['function_name']:
                        cnt += 1
                        print(doc['CVE'], doc['fixed_version'], func)
                        wr.writerow([doc['CVE'], doc['fixed_version'], func])
                if cnt > 0:
                    build_version.add(doc['fixed_version'])
    print(lib, list(build_version))

# per package version (string)
def generate_func_list_for_string_per_package(lib, lib_ver, fw_ver):
    collection = db[lib]
    build_version = {lib_ver}
    with open('func_list_' + ven + '/' + lib + '_' + fw_ver + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'affected_since_version' in doc.keys():
                if version.parse(lib_ver) < version.parse(doc['affected_since_version']):
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue
            if version.parse(lib_ver) >= version.parse(doc['fixed_version']):
                print('skip', doc['CVE'], '(fixed in', doc['fixed_version'], ')')
                continue
            if 'function_name' not in doc.keys():
                print('error', doc['CVE'], 'has no function name')
            else:
                if 'update_function_name' in doc.keys():
                    funcs = doc['update_function_name'][1:-1].split(', ')
                else:
                    funcs = doc['function_name'][1:-1].split(', ')
                cnt = 0
                for func in funcs:
                    cnt += 1
                    print(doc['CVE'], doc['fixed_version'], func)
                    wr.writerow([doc['CVE'], doc['fixed_version'], func[1:-1]])
                if cnt > 0:
                    build_version.add(doc['fixed_version'])
    print(lib, list(build_version))

lib_format_dic = {
    'curl': 'list',
    'dbus': 'list',
    'dnsmasq': 'list',
    'e2fsprogs': 'list',
    'expat': 'string',
    'libarchive': 'string',
    'libgcrypt': 'string',
    'libmodbus': 'list',
    'libpcap': 'list',
    'libssh2': 'list',
    'libtirpc': 'list',
    'libxml2': 'string',
    'mosquitto': 'list',
    'ncurses': 'list',
    'openssh': 'string',
    'openssl': 'list',
    'perl': 'list',
    'util-linux': 'list',
    'zlib': 'list'
}

ven = config.ven
fw_ver = config.fw_ver
lib = config.lib
lib_ver = config.lib_ver

if lib_format_dic[lib] == 'list':
    generate_func_list_for_list_per_package(lib, lib_ver, fw_ver)
elif lib_format_dic[lib] == 'string':
    generate_func_list_for_string_per_package(lib, lib_ver, fw_ver)
else:
    print('no package', lib)