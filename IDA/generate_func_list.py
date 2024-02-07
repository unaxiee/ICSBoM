from pymongo import MongoClient
import csv
from packaging import version

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
def generate_func_list_for_list_per_package(lib, ver):
    collection = db[lib]
    build_version = {ver}
    with open('func_list/' + lib + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'affected_since_version' in doc.keys():
                if version.parse(ver) < version.parse(doc['affected_since_version']):
                # for openssl only
                # if ver < doc['affected_since_version']:
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue
            if version.parse(ver) >= version.parse(doc['fixed_version']):
            # for openssl only
            # if ver >= doc['fixed_version']:
                print('skip', doc['CVE'], '(fixed in', doc['fixed_version'], ')')
                continue
            if 'function_name' not in doc.keys():
                print('error', doc['CVE'], 'has no function name')
            else:
                build_version.add(doc['fixed_version'])
                if 'update_function_name' in doc.keys():
                    for update_func in doc['update_function_name']:
                        print(doc['CVE'], doc['fixed_version'], update_func)
                        wr.writerow([doc['CVE'], doc['fixed_version'], update_func])
                else:
                    for func in doc['function_name']:
                        print(doc['CVE'], doc['fixed_version'], func)
                        wr.writerow([doc['CVE'], doc['fixed_version'], func])
    print(lib, list(build_version))

# per package version (string)
def generate_func_list_for_string_per_package(lib, ver):
    collection = db[lib]
    build_version = {ver}
    with open('func_list/' + lib + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'affected_since_version' in doc.keys():
                if version.parse(ver) < version.parse(doc['affected_since_version']):
                    print('skip', doc['CVE'], '(affecting since', doc['affected_since_version'], ')')
                    continue
            if version.parse(ver) >= version.parse(doc['fixed_version']):
                print('skip', doc['CVE'], '(fixed in', doc['fixed_version'], ')')
                continue
            if 'function_name' not in doc.keys():
                print('error', doc['CVE'], 'has no function name')
            else:
                build_version.add(doc['fixed_version'])
                if 'update_function_name' in doc.keys():
                    funcs = doc['update_function_name'][1:-1].split(', ')
                else:
                    funcs = doc['function_name'][1:-1].split(', ')
                for func in funcs:
                    print(doc['CVE'], doc['fixed_version'], func)
                    wr.writerow([doc['CVE'], doc['fixed_version'], func[1:-1]])
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
    'util-linux': 'list'
}

lib = 'libxml2'
ver = '2.9.10'
if lib_format_dic[lib] == 'list':
    generate_func_list_for_list_per_package(lib, ver)
elif lib_format_dic[lib] == 'string':
    generate_func_list_for_string_per_package(lib, ver)
else:
    print('no package', lib)