from tlsh import diff
import json
import pandas as pd
from openpyxl import load_workbook

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

def match_function(ref, build_dic, fw_j):
    list_len_list = [1, 25]
    found = False

    for list_len in list_len_list:
        select_list = create_select_list(list_len)
    
        for key, value in fw_j.items():
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
        return ''

    max_sim_bb = 0
    select = []
    for select_item in select_list:
        sim_bb = 0
        for bb_hash in build_dic['bb_hash']:
            for bb_hash_sel in select_item['bb_hash']:
                if bb_hash == bb_hash_sel:
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
            elif list_len == 25:
                if len(select) > 1:
                    print(ref, "has the most bb_hash", max_sim_bb, "with tie\n")
                    return 'Top-25 (' + str(max_sim_bb) + ') (tie)'
                else:
                    print(ref, "has the most bb_hash", max_sim_bb, '\n')
                    return 'Top-25+bb_hash (' + str(max_sim_bb) + ')'
            return
        
    print(ref, "doesn't have the most bb_hash\n")
    return 'Top-25 (not max)'

def evaluate(package, fw):
    excel = 'func_match.xlsx'
    data = pd.read_excel(excel, sheet_name=package, skiprows=[0])

    if fw == 'pfc':
        col = 3
    elif fw == 'cc':
        col = 5
    else:
        print("Don't support family", fw)
        return

    with pd.ExcelWriter(excel, mode='a', if_sheet_exists='overlay') as writer:
    
        for index, row in data.iterrows():

            with open('disasm_hash/' + row['lib'] + '-build_hash.json', 'r') as f:
                build_j = json.load(f)
            
            if row['function'] not in build_j.keys():
                print("Don't find function", row['function'], "in", row['lib'])
                continue

            with open('disasm_hash/' + row['lib'] +'-fw-' + fw + '_hash.json', 'r') as f:
                fw_j = json.load(f)

            print(row['function'])
            result = match_function(row[fw + '-reference'], build_j[row['function']], fw_j)
            df = pd.DataFrame([result])
            df.to_excel(writer, sheet_name=package, startrow=index+2, startcol=col, header=False, index=False)

evaluate('libssh2', 'pfc')