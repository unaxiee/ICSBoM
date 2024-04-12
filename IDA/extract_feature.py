from idautils import *
from idaapi import *
import csv
import json

# 2.9.10, 2.9.11
# libxml_special_func = ['xmlParsePEReference']

# 2.9.13, 2.9.14
libxml_special_func = ['xmlAddID', 'xmlParsePEReference']

fw_func_list = []

def get_func_for_build():
    func_name = set()
    with open('func_list.csv', 'r') as f:
        r = csv.reader(f, delimiter=',')
        for row in r:
            func_name.add(row[-1])
            if 'libxml2' in file_name:
                func_name.add(row[-1] + '__internal_alias')
                if row[-1] in libxml_special_func:
                    func_name.remove(row[-1] + '__internal_alias')
                    func_name.add(row[-1] + '__internal_alias_0')
    return func_name


def dump_function_details(ea):
    disasm = dict()
    cnt = 0

    for bb in FlowChart(get_func(ea), flags=FC_PREDS):
        if bb.start_ea != bb.end_ea:
            bb_disasm = []
            for head in Heads(bb.start_ea, bb.end_ea):
                bb_disasm.append(GetDisasm(head))

            preds_list = []
            if bb.preds():
                for preds_bb in bb.preds():
                    preds_list.append(preds_bb.start_ea)

            succs_list = []
            if bb.succs():
                for succs_bb in bb.succs():
                    succs_list.append(succs_bb.start_ea)

            disasm[bb.start_ea] = {
                'disasm': bb_disasm,
                'preds': preds_list,
                'succs': succs_list
            }
            cnt += 1

    if 'fw' not in file_name:
        disasm['bb_num'] = cnt
        return disasm
    else:
        if cnt > 5:
            disasm['bb_num'] = cnt
            return disasm
        elif get_func_name(ea) in fw_func_list:
            print(get_func_name(ea), cnt, 'bbs')
            disasm['bb_num'] = cnt
            return disasm
        else:
            return None


file_name = get_root_filename()

procname = get_inf_structure().procname.lower()
disasm_dic = {'arch': procname}

# for reference
if 'fw' not in file_name:
    func_name = get_func_for_build()
    found_func = set()
    for ea in Functions():
        name = get_func_name(ea)
        if name in func_name:
            disasm = dump_function_details(ea)
            if disasm:
                print(name, disasm['bb_num'], 'bbs')
                del disasm['bb_num']
                # special case for libxml2
                if 'libxml2' in file_name:
                    if '__internal_alias' in name:
                        found_func.add(name)
                        name = name[:name.index('__internal_alias')]
                    else:
                        found_func.add(name + '__internal_alias')
                disasm_dic[name] = disasm
                found_func.add(name)
            else:
                print('Skip', name, 'less than five basic blocks')
    if 'libxml2' not in file_name:
        print('Extracted', len(found_func), '/', len(func_name))
        print('Cannot extract', func_name - found_func)
    else:
        print('Extracted', len(found_func) // 2, '/', len(func_name) // 2)
        print('Cannot extract')
        for func in func_name - found_func:
            if '__internal_alias' in func:
                continue
            print(func)
# for firmware
else:
    func_cnt = 0
    for ea in Functions():
        name = get_func_name(ea)
        disasm = dump_function_details(ea)
        if disasm:
            del disasm['bb_num']
            if 'libxml2' in file_name:
                if '__internal_alias' in name:
                    name = name[:name.index('__internal_alias')]
            disasm_dic[name] = disasm
            func_cnt += 1
    disasm_dic['num'] = func_cnt
    print(func_cnt, 'done')

disasm_json = json.dumps(disasm_dic)
with open('../../output/' + file_name + '_disasm.json', 'w') as f:
    f.write(disasm_json)