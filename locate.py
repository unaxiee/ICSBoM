from tlsh import diff
import json
import pandas as pd
import csv
import os

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

def match_function(ref, build_dic, fw_j, max_num):
    if build_dic['func_hash'] == 'TNULL':
        return 'Too few basic blocks'
    
    list_len_list = [1, max_num]
    found = False

    for list_len in list_len_list:
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
                print('Found in Top-', list_len)
                found = True
                break
        
        if found:
            break

    if not found:
        print('Not found in Top-', list_len, '\n')
        return 'Not Found'

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
            if list_len == 1:
                print(ref, "has bb_hash", max_sim_bb, '\n')
                return 'Top-1 (' + str(max_sim_bb) + ')'
            elif list_len == list_len_list[-1]:
                if len(select) > 1:
                    print(ref, "has the most bb_hash", max_sim_bb, "with tie\n")
                    return 'Top-' + str(list_len_list[-1]) + '(' + str(max_sim_bb) + ') (tie)'
                else:
                    print(ref, "has the most bb_hash", max_sim_bb, '\n')
                    return 'Top-' + str(list_len_list[-1]) + '+bb_hash (' + str(max_sim_bb) + ')'
        
    print(ref, "doesn't have the most bb_hash\n")
    return 'Top-' + str(list_len_list[-1]) + '(not max)'

def evaluate(package, pkg_ver, fw, ver, max_num):
    
    data = pd.read_csv('util/func_lib/' + package + '/' + package + '_fw-' + fw + '-' + ver + '_func_lib.csv')

    dir_output = 'output_function_locating/' + package + '/'
    if not os.path.isdir(dir_output):
        os.makedirs(dir_output)

    if os.path.isfile(dir_output + package + '_' + fw + '-' + ver + '_result.csv'):
        os.remove(dir_output + package + '_' + fw + '-' + ver + '_result.csv')

    for idx, row in data.iterrows():
        if row['lib'] == 'not found':   # afftected function cannot be found in binary
            print(row['function'], 'cannot be found in binary\n')
            continue

        if row['name'] == 'not match':   # stripped file cannot be matched by IDA
            print(row['function'], 'cannot be matched in firmware binary\n')
            continue

        if not os.path.isfile('disasm_hash/' + fw + '/' + ver + '/' + package + '/' + row['lib'] + '-fw-' + fw + '-' + ver + '_hash.json'):
            print(row['lib'], 'cannot be found in firmware image\n')
            continue

        with open('disasm_hash/' + fw + '/' + ver + '/' + package + '/' + row['lib'] + '-fw-' + fw + '-' + ver + '_hash.json', 'r') as f:
            fw_j = json.load(f)
            del fw_j['num']
        
        with open('disasm_hash/' + fw + '/' + ver + '/' + package + '/' + row['lib'] + '-' + pkg_ver + '_hash.json', 'r') as f:
            build_j = json.load(f)

        if row['function'] not in build_j.keys():
            print(row['function'], 'is not extracted from built package\n')
            continue
        
        print(row['function'])

        result = match_function(row['name'], build_j[row['function']], fw_j, max_num)

        with open(dir_output + package + '_' + fw + '-' + ver + '_result.csv', 'a') as f:
            wr = csv.writer(f)
            wr.writerow([row['function'], row['lib'], result])

evaluate('libxml2', '2.9.10', 'pfc', '21', 500)