from tlsh import diff
import json
import pandas as pd
import csv
import os
from util import config

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

def evaluate(lib, lib_ver, fw, fw_ver, ven):
    
    data = pd.read_csv('IDA/func_lib/' + lib + '/' + ven + '_' + fw + '_' + fw_ver + '.csv')

    dir_output = 'output_function_locating/' + lib + '/'
    if not os.path.isdir(dir_output):
        os.makedirs(dir_output)

    file_output = dir_output + ven + '_' + fw + '_' + fw_ver + '.csv'
    if os.path.isfile(file_output):   # remove old output
        os.remove(file_output)

    for idx, row in data.iterrows():
        if row['lib'] == 'not found':   # afftected function cannot be found in reference binary
            print(row['function'], 'cannot be found in reference binary\n')
            continue

        if row['name'] == 'not match':   # affected function cannot be matched in target binary due to stripped file
            print(row['function'], 'cannot be matched in target binary\n')
            continue

        # if not os.path.isfile('disasm/disasm_hash/' + fw + '/' + ver + '/' + package + '/' + row['lib'] + '-fw-' + fw + '-' + ver + '_hash.json'):   # target binary cannot be found in firmware image
        if not os.path.isfile('disasm/disasm_hash/' + ven + '/' + lib + '/' + row['lib'] + '_fw_' + fw + '_' + fw_ver + '_hash.json'):
            print(row['lib'], 'cannot be found in firmware image\n')
            continue

        # with open('disasm/disasm_hash/' + fw + '/' + ver + '/' + package + '/' + row['lib'] + '-fw-' + fw + '-' + ver + '_hash.json', 'r') as f:
        with open('disasm/disasm_hash/' + ven + '/' + lib + '/' + row['lib'] + '_fw_' + fw + '_' + fw_ver + '_hash.json', 'r') as f:
            fw_j = json.load(f)
            tol_num = fw_j['num']
            del fw_j['num']

        if row['name'] not in fw_j.keys():   # affected function is not extracted from target binary
            print(row['function'], 'is not extracted from target binary\n')
            continue
        
        # with open('disasm/disasm_hash/' + fw + '/' + ver + '/' + package + '/' + row['lib'] + '-' + pkg_ver + '_hash.json', 'r') as f:
        with open('disasm/disasm_hash/' + fw + '/' + lib + '/' + row['lib'] + '_' + lib_ver + '_hash.json', 'r') as f:
            build_j = json.load(f)

        if row['function'] not in build_j.keys():   # affected function is not extracted from reference binary
            print(row['function'], 'is not extracted from reference binary\n')
            continue
        
        print(row['function'])

        result = match_function(row['name'], build_j[row['function']], fw_j, tol_num)

        with open(file_output, 'a') as f:
            wr = csv.writer(f)
            wr.writerow([row['function'], row['lib'], result])

evaluate(config.lib, config.lib_ver, config.fw, config.fw_ver, config.ven)