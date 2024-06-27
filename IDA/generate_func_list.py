from pymongo import MongoClient
import csv
from packaging import version
import sys
sys.path.append('/media/yongyu/Data/ICS/ICSBoM')
from util import config
import os

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


def generate_func_list_for_rest(lib, lib_ver, fw_ver):
    collection = db[lib]
    build_version = {lib_ver}

    dir_ven = 'func_list_' + ven + '/'
    if not os.path.isdir(dir_ven):
        os.makedirs(dir_ven)
    with open(dir_ven + lib + '_' + fw_ver + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'affected_since_version' in doc.keys() and version.parse(lib_ver) < version.parse(doc['affected_since_version']):
                print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                continue

            if doc['fixed_version'] != 'master' and version.parse(lib_ver) >= version.parse(doc['fixed_version']):
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


def generate_func_list_for_openssl(lib, lib_ver, fw_ver):
    if lib_ver[0] == '1':
        collection = db[lib + '_' + lib_ver[:-1]]
    elif lib_ver[0] == '3':
        collection = db[lib + '_' + lib_ver.rsplit('.', 1)[0]]
    build_version = {lib_ver}

    dir_ven = 'func_list_' + ven + '/'
    if not os.path.isdir(dir_ven):
        os.makedirs(dir_ven)
    with open(dir_ven + lib + '_' + fw_ver + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'affected_since_version' in doc.keys():
                if lib_ver[0] == '3' and version.parse(lib_ver) < version.parse(doc['affected_since_version']):
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue
                elif lib_ver[0] == '1' and lib_ver < doc['affected_since_version']:
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue

            if lib_ver[0] == '3' and version.parse(lib_ver) >= version.parse(doc['fixed_version']):
                print('skip', doc['CVE'], '(fixed in', doc['fixed_version'], ')')
                continue
            elif lib_ver[0] == '1' and lib_ver >= doc['fixed_version']:
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


lib_list = [
    'curl',
    'dbus',
    'dnsmasq',
    'e2fsprogs',
    'expat',
    'libarchive',
    'libgcrypt',
    'libmodbus',
    'libpcap',
    'libssh2',
    'libtirpc',
    'libxml2',
    'mosquitto',
    'ncurses',
    'openssh',
    'openssl',
    'perl',
    'util-linux',
    'zlib'
]

ven = config.ven
fw_ver = config.fw_ver
lib = config.lib
lib_ver = config.lib_ver

if lib == 'openssl':
    generate_func_list_for_openssl(lib, lib_ver, fw_ver)
elif lib in lib_list:
    generate_func_list_for_rest(lib, lib_ver, fw_ver)
else:
    print('no', lib, 'found in CVE database')