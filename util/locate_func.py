import subprocess
import os
import csv

lib = 'zlib'
fw = 'fw-iot2000-3'
flag = 'search'

func_set = set()
with open('../IDA/func_list/' + lib + '_func_list.csv', 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line[:-1].split(',')
        func_set.add(line[-1])
print(len(func_set))


def search_in_select_lib(flag):
    func_dic = {}
    for func in func_set:
        func_dic[func] = []

    path = '../select_lib/' + fw + '/'
    for lib_ver in os.listdir(path):
        if lib in lib_ver:
            print(lib_ver)

            if flag == 'search':
                path += lib_ver + '/usr/'
                for dir in os.listdir(path):
                    if dir in ['lib']:
                        path_bin = path + dir + '/'
                        for bin in os.listdir(path_bin):
                            if os.path.isfile(path_bin + '/' + bin):
                                strings_out = subprocess.run(['strings', path_bin + '/' + bin], capture_output=True, text=True).stdout.split('\n')
                                for func in func_set:
                                    if func in strings_out:
                                        func_dic[func].append(bin)
                cnt = 0
                for key, value in func_dic.items():
                    print(key, value)
                    if len(value) > 0:
                        cnt += 1
                print(cnt)

            elif flag == 'locate':
                path += lib_ver
                for bin in os.listdir(path):
                    strings_out = subprocess.run(['strings', path + '/' + bin], capture_output=True, text=True).stdout.split('\n')
                    for func in func_set:
                        if func in strings_out:
                            func_dic[func].append(bin)
                dir_func_lib = 'func_lib/' + lib + '/'
                if not os.path.isdir(dir_func_lib):
                    os.makedirs(dir_func_lib)
                with open('func_lib/' + lib + '/' + lib + '_' + fw + '_func_lib.csv', 'w') as f:
                    wr = csv.writer(f)
                    wr.writerow(['function', 'lib', 'name'])
                    for key, value in func_dic.items():
                        if len(value) > 0:
                            wr.writerow([key, value[0].split('.')[0]])
                        else:
                            wr.writerow([key, 'not found'])
            
            break

def generate_func_lib(func_lib):
    dir_func_lib = 'func_lib/' + lib + '/'
    if not os.path.isdir(dir_func_lib):
        os.makedirs(dir_func_lib)
    with open('func_lib/' + lib + '/' + lib + '_' + fw + '_func_lib.csv', 'w') as f:
        wr = csv.writer(f)
        wr.writerow(['function', 'lib', 'name'])
        for func in func_set:
            wr.writerow([func, func_lib, func])


generate_func_lib('libz')