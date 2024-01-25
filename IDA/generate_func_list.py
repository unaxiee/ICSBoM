from pymongo import MongoClient
import csv

client = MongoClient('localhost', 27017)
db = client['lib_vul_db']

# for function name in list format
def generate_func_list_for_list(lib):
    collection = db[lib]
    with open('func_list/' + lib + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            if 'function_name' in doc.keys():
                for func in doc['function_name']:
                    wr.writerow([doc['CVE'], doc['fixed_version'], func])

# for function name in string format
def generate_func_list_for_string(lib):
    collection = db[lib]
    with open('func_list/' + lib + '_func_list.csv', 'w') as f:
        wr = csv.writer(f)
        for doc in collection.find():
            # ignore empty function name
            if len(doc['function_name']) > 2:
                funcs = doc['function_name'][1:-1].split(', ')
                for func in funcs:
                    wr.writerow([doc['CVE'], doc['fixed_version'], func[1:-1]])

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

generate_func_list_for_list('perl')