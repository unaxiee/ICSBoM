from tlsh import diff
import json

dir = 'disasm_hash/'

lib_name = 'libssh2'

firmware_fam = 'pfc'

with open(dir + lib_name + '-build_hash.json', 'r') as f:
    build_j = json.load(f)

with open(dir + lib_name +'-fw-' + firmware_fam + '_hash.json', 'r') as f:
    fw_j = json.load(f)


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


tar_func = 'packet_ask'
tar_addr = '28098'

for key, value in build_j.items():
    if tar_func not in key:
        continue
    print(key)
    list_len = 100
    select_list = create_select_list(list_len)
    
    for key_can, value_can in fw_j.items():

        idx_sel, diff_sel = get_max_diff_sel(select_list)

        diff_tmp = diff(value['func_hash'], value_can['func_hash'])
        
        if diff_tmp < diff_sel:
            select_list[idx_sel]['func'] = key_can
            select_list[idx_sel]['diff'] = diff_tmp
            select_list[idx_sel]['bb_hash'] = value_can['bb_hash']

    
    for select_item in select_list:
        # if key == select_item['func']:
        if tar_addr in select_item['func']:
            print('Found in Top-', list_len)


    max_sim_bb = 0
    select = 'none'
    for select_item in select_list:
        sim_bb = 0
        for bb_hash in value['bb_hash']:
            for bb_hash_sel in select_item['bb_hash']:
                if bb_hash == bb_hash_sel:
                    sim_bb += 1
                    break
        # print(select_item['func'], select_item['diff'], sim_bb)
        if sim_bb > max_sim_bb:
            max_sim_bb = sim_bb
            select = select_item['func']
        if tar_addr in select_item['func']:
            print(select_item['func'], select_item['diff'], sim_bb)
    print(select, max_sim_bb, '\n')