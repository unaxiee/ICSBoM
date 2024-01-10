from pymongo import MongoClient
import csv

lib = 'expat'

client = MongoClient('localhost', 27017)
db = client['lib_vul_db']
collection = db[lib]

# for function name in list format
# with open('func_list/' + lib + '_func_list.csv', 'w') as f:
#     wr = csv.writer(f)
#     for doc in collection.find():
#         if 'function_name' in doc.keys():
#             for func in doc['function_name']:
#                 wr.writerow([doc['CVE'], doc['fixed_version'], func])

# for function name in string format
with open('func_list/' + lib + '_func_list.csv', 'w') as f:
    wr = csv.writer(f)
    for doc in collection.find():
        # if 'function_name' in doc.keys():
        funcs = doc['function_name'][1:-1].split(', ')
        for func in funcs:
            wr.writerow([doc['CVE'], doc['fixed_version'], func[1:-1]])