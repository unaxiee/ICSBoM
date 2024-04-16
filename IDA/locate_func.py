import subprocess
import os
import csv
import sys
sys.path.append('/media/yongyu/Data/ICS/FSS')
from util import config

lib = config.lib
vendor = config.ven
fw = config.fw
fw_ver = config.fw_ver


func_set = set()
with open('func_list_' + vendor + '/' + lib + '_' + fw_ver + '_func_list.csv', 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line[:-1].split(',')
        func_set.add(line[-1])
print(len(func_set))


def search_in_select_lib():
    path = 'select_lib/'
    for lib in os.listdir(path):
        path_lib = path + lib
        if os.path.isfile(path_lib):
            strings_out = subprocess.run(['strings', path_lib], capture_output=True, text=True).stdout.split('\n')
            for func in func_set:
                if func in strings_out:
                    print(func, lib)
                

def generate_func_lib(func_lib):
    dir_func_lib = 'func_lib/' + lib + '/'
    if not os.path.isdir(dir_func_lib):
        os.makedirs(dir_func_lib)
    with open(dir_func_lib + lib + '_fw-' + fw + '-' + fw_ver + '_func_lib.csv', 'w') as f:
        wr = csv.writer(f)
        wr.writerow(['function', 'lib', 'name'])
        for func in func_set:
            wr.writerow([func, func_lib, func])


generate_func_lib('ssh')
# search_in_select_lib()