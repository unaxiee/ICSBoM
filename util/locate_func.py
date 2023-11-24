import subprocess
import os
import csv

lib = 'dbus'
fw = 'fw-iot2000-3'

func_set = set()
with open('../IDA/func_list/' + lib + '_func_list.csv', 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line[:-1].split(',')
        func_set.add(line[-1])

func_dic = {}
for func in func_set:
    func_dic[func] = []

path = '../select_lib/' + fw + '/'
for lib_ver in os.listdir(path):
    if lib in lib_ver:
        print(lib_ver)
        # path += lib_ver + '/usr/'
        # for dir in os.listdir(path):
        #     if dir in ['bin', 'lib']:
        #         path_bin = path + dir + '/'
        #         for bin in os.listdir(path_bin):
        #             if os.path.isfile(path_bin + '/' + bin):
        #                 strings_out = subprocess.run(['strings', path_bin + '/' + bin], capture_output=True, text=True).stdout.split('\n')
        #                 for func in func_set:
        #                     if func in strings_out:
        #                         func_dic[func].append(bin)
        path += lib_ver
        for bin in os.listdir(path):
            strings_out = subprocess.run(['strings', path + '/' + bin], capture_output=True, text=True).stdout.split('\n')
            for func in func_set:
                if func in strings_out:
                    func_dic[func].append(bin)

for key, value in func_dic.items():
    print(key, value)

with open('test.csv', 'w') as f:
    wr = csv.writer(f)
    wr.writerow(['function', 'lib'])

    for key, value in func_dic.items():
        print(key, value)
        if len(value) > 0:
            wr.writerow([key, value[0].split('.')[0]])
        else:
            wr.writerow([key])