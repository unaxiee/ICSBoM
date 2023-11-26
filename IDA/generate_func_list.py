from pymongo import MongoClient
import csv

lib = 'openssl'

client = MongoClient('localhost', 27017)
db = client['lib_vul_db']
collection = db[lib]


with open('func_list/' + lib + '_func_list.csv', 'w') as f:
    wr = csv.writer(f)
    for doc in collection.find():
        for func in doc['function_name']:
            wr.writerow([doc['CVE'], doc['fixed_version'], func])