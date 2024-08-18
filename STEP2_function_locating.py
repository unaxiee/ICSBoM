from tlsh import diff
import json
import pandas as pd
import csv
import os
from util import config
from util.parse_hash import sanitize_arm_for_hash, sanitize_x86_for_hash
from util.parse_norm import sanitize_arm_for_norm, sanitize_x86_for_norm


def create_select_list(num):
    select_list = []
    for i in range(num):
        select_list.append(
            {
                'func': 'test',
                'diff': 1000,
                'bb_hash': []
            }
        )
    return select_list


def get_max_diff_sel(select_list):
    diff_max_tmp = 0
    idx_tmp = -1
    for i in range(len(select_list)):
        if select_list[i]['diff'] > diff_max_tmp:
            diff_max_tmp = select_list[i]['diff']
            idx_tmp = i
    return idx_tmp, diff_max_tmp


def match_function(ref, build_dic, fw_j, tol_num):
    if build_dic['func_hash'] == 'TNULL':
        return 'Too few basic blocks'
    
    max_num = tol_num // 3 * 2
    list_len = 1
    found = False

    while not found and list_len <= max_num:
        select_list = create_select_list(list_len)
    
        for key, value in fw_j.items():
            if value['func_hash'] == 'TNULL':
                continue
            idx_sel, diff_sel = get_max_diff_sel(select_list)
            diff_tmp = diff(build_dic['func_hash'], value['func_hash'])
            
            if diff_tmp < diff_sel:
                select_list[idx_sel]['func'] = key
                select_list[idx_sel]['diff'] = diff_tmp
                select_list[idx_sel]['bb_hash'] = value['bb_hash']

        for select_item in select_list:
            if select_item['func'] == ref:
                found = True
                break

        if not found:
            if list_len == 1:
                list_len = 25
            elif list_len == 25:
                list_len = 50
            else:
                list_len += 50
            continue


        max_sim_bb = 0
        select = []
        for select_item in select_list:
            if len(select_item['bb_hash']) == 0:
                continue
            sim_bb = 0
            for key_build, value_bb_hash in build_dic['bb_hash'].items():
                for key_sel, value_bb_hash_sel in select_item['bb_hash'].items():
                    if value_bb_hash == value_bb_hash_sel:
                        sim_bb += 1
                        break

            if sim_bb > max_sim_bb:
                max_sim_bb = sim_bb
                select = []
                select.append(select_item['func'])
            elif sim_bb == max_sim_bb:
                select.append(select_item['func'])
        
        for func in select:
            if func == ref:
                if len(select) > 1:
                    print(f'{ref} found in Top-{list_len} with the most {max_sim_bb} bb_hash with tie\n')
                    return f'Top-{list_len} + bb_hash {str(max_sim_bb)} (tie)'
                else:
                    print(f'{ref} found in Top-{list_len} with the most {max_sim_bb} bb_hash \n')
                    return f'Top-{list_len} + bb_hash {str(max_sim_bb)}'
        
        print(f'{ref} found in Top-{list_len} but does not have the most bb_hash ({max_sim_bb})\n')
        return f'Top-{list_len} + bb_hash {str(max_sim_bb)} (not max)'
    
    print(f'{ref} not found in Top-{max_num}\n')
    return 'Not Found'

def evaluate(lib, lib_ver, fw, fw_ver, ven, compiler):
    
    data = pd.read_csv('IDA/func_lib/' + lib + '/' + ven + '_' + fw + '_' + fw_ver + '.csv')

    dir_output = 'output_function_locating/' + lib + '/'
    if not os.path.isdir(dir_output):
        os.makedirs(dir_output)

    file_output = dir_output + ven + '_' + fw + '_' + fw_ver + '.csv'
    if compiler != '':
        file_output = dir_output + ven + '_' + fw + '_' + fw_ver + '_' + compiler + '.csv'
    if os.path.isfile(file_output):   # remove old output
        os.remove(file_output)

    for idx, row in data.iterrows():
        if row['lib'] == 'not found':   # afftected function cannot be found in reference binary
            print(row['function'], 'cannot be found in reference binary\n')
            continue

        if row['name'] == 'not match':   # affected function cannot be matched in target binary due to stripped file
            print(row['function'], 'cannot be matched in target binary\n')
            continue

        if not os.path.isfile('disasm/disasm_hash/' + ven + '/' + lib + '/' + row['lib'] + '_fw_' + fw + '_' + fw_ver + '_hash.json'):   # target binary cannot be found in firmware image
            print(row['lib'], 'cannot be found in firmware image\n')
            continue

        with open('disasm/disasm_hash/' + ven + '/' + lib + '/' + row['lib'] + '_fw_' + fw + '_' + fw_ver + '_hash.json', 'r') as f:
            fw_j = json.load(f)
            tol_num = fw_j['num']
            del fw_j['num']

        if row['name'] not in fw_j.keys():   # affected function is not extracted from target binary
            print(row['function'], 'is not extracted from target binary\n')
            continue
        
        if compiler != '':
            with open('disasm/disasm_hash/' + ven + '/' + lib + '/' + row['lib'] + '_' + lib_ver + '_' + compiler + '_hash.json', 'r') as f:
                build_j = json.load(f)
        else:
            with open('disasm/disasm_hash/' + ven + '/' + lib + '/' + row['lib'] + '_' + lib_ver + '_hash.json', 'r') as f:
                build_j = json.load(f)

        if row['function'] not in build_j.keys():   # affected function is not extracted from reference binary
            print(row['function'], 'is not extracted from reference binary\n')
            continue

        result = match_function(row['name'], build_j[row['function']], fw_j, tol_num)

        with open(file_output, 'a') as f:
            wr = csv.writer(f)
            wr.writerow([row['function'], row['lib'], result])


with open('util/fw_lib_list/' + config.ven + '.csv', 'r') as f:
    lines = f.readlines()

for line in lines:
    line = line[:-1].split(',')
    config.fw = line[1]
    config.fw_ver = line[2]
    config.lib = line[3]
    config.lib_ver = line[4]

    # if config.lib != config.test_lib:
    #     continue
    # if config.fw_ver != config.test_fw_ver:
    #     continue
    print(line)

    dir_raw = 'disasm/disasm_raw/' + config.ven + '/' + config.lib +'/'
    dir_hash = 'disasm/disasm_hash/' + config.ven + '/' + config.lib + '/'
    if not os.path.isdir(dir_hash):
        os.makedirs(dir_hash)
    dir_norm = 'disasm/disasm_norm/' + config.ven + '/' + config.lib + '/'
    if not os.path.isdir(dir_norm):
        os.makedirs(dir_norm)
    
    for file_name in os.listdir(dir_raw):
        if 'fw' in file_name:
            if config.fw not in file_name or config.fw_ver not in file_name:
                continue
            hash_dic = {}
            norm_dic = {}
            with open(dir_raw + file_name, 'r') as f:
                contents_j = json.load(f)
            arch = contents_j['arch']
            del contents_j['arch']
            num = contents_j['num']
            del contents_j['num']
            if arch == 'arm':
                hash_dic = sanitize_arm_for_hash(contents_j)
                norm_dic = sanitize_arm_for_norm(contents_j)
            else:
                hash_dic = sanitize_x86_for_hash(contents_j)
                norm_dic = sanitize_x86_for_norm(contents_j)
            hash_dic['num'] = num
            norm_dic['num'] = num
            hash_json = json.dumps(hash_dic)
            norm_json = json.dumps(norm_dic)
            with open(dir_hash + file_name.rsplit('_', 1)[0] + '_hash.json', 'w') as f:
                f.write(hash_json)
            with open(dir_norm + file_name.rsplit('_', 1)[0] + '_norm.json', 'w') as f:
                f.write(norm_json)
            dic_func_lib = {}

            with open('IDA/func_lib/' + config.lib + '/' + config.ven + '_' + config.fw + '_' + config.fw_ver + '.csv', 'r') as f_func_lib:
                reader_func_lib = csv.reader(f_func_lib)
                next(reader_func_lib, None)
                for func_lib in reader_func_lib:
                    dic_func_lib[func_lib[0]] = [func_lib[1], func_lib[2]]
            with open(dir_norm + config.fw + '_' + config.fw_ver + '_func_list.csv', 'w') as f:
                writer = csv.writer(f)
                with open('IDA/func_list_' + config.ven + '/' + config.lib + '_' + config.fw + '_' + config.fw_ver + '_func_list.csv', 'r') as f_func_list:
                    reader_func_list = csv.reader(f_func_list)
                    for func_list in reader_func_list:
                        writer.writerow([func_list[0], config.lib_ver, func_list[1], dic_func_lib[func_list[2]][0], func_list[2], dic_func_lib[func_list[2]][1]])

        else:
            if config.lib_ver in file_name:
                if config.test_compiler != '' and config.test_compiler not in file_name:
                    continue
                if os.path.isfile(dir_norm + file_name.rsplit('_', 1)[0] + '_hash.json'):
                    continue
                hash_dic = {}
                with open(dir_raw + file_name, 'r') as f:
                    contents_j = json.load(f)
                arch = contents_j['arch']
                del contents_j['arch']
                if arch == 'arm':
                    hash_dic = sanitize_arm_for_hash(contents_j)
                else:
                    hash_dic = sanitize_x86_for_hash(contents_j)
                hash_json = json.dumps(hash_dic)
                with open(dir_hash + file_name.rsplit('_', 1)[0] + '_hash.json', 'w') as f:
                    f.write(hash_json)
            if os.path.isfile(dir_norm + file_name.rsplit('_', 1)[0] + '_norm.json'):
                continue
            norm_dic = {}
            with open(dir_raw + file_name, 'r') as f:
                contents_j = json.load(f)
            arch = contents_j['arch']
            del contents_j['arch']
            if arch == 'arm':
                disasm_dic = sanitize_arm_for_norm(contents_j)
            else:
                disasm_dic = sanitize_x86_for_norm(contents_j)
            disasm_json = json.dumps(disasm_dic)
            with open(dir_norm + file_name.rsplit('_', 1)[0] + '_norm.json', 'w') as f:
                f.write(disasm_json)
            

    evaluate(config.lib, config.lib_ver, config.fw, config.fw_ver, config.ven, config.test_compiler)