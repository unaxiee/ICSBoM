from idautils import *
from idaapi import *
import csv
import json


def get_func_for_build():
    func_name = set()
    with open('func_list.csv', 'r') as f:
        r = csv.reader(f, delimiter=',')
        for row in r:
            func_name.add(row[-1])
    return func_name

def dump_function_details(ea):
    disasm = dict()
    cnt = 0

    for bb in FlowChart(get_func(ea), flags=FC_PREDS):
        if bb.start_ea != bb.end_ea:
            bb_disasm = []
            for head in Heads(bb.start_ea, bb.end_ea):
                bb_disasm.append(GetDisasm(head))
            disasm[bb.start_ea] = bb_disasm
            cnt += 1

    if cnt > 5:
        preds_list = []
        if bb.preds():
            for preds_bb in bb.preds():
                preds_list.append(preds_bb.start_ea)
            print(preds_list)
        disasm['preds'] = preds_list
        succs_list = []
        if bb.succs():
            for succs_bb in bb.succs():
                succs_list.append(succs_bb.start_ea)
            print(succs_list)
        disasm['succs'] = succs_list
        return disasm
    else:
        return None


file_name = get_root_filename()

procname = get_inf_structure().procname.lower()
disasm_dic = {'arch': procname}

if 'fw' not in file_name:
    func_name = get_func_for_build()
    for ea in Functions():
        name = get_func_name(ea)
        if name in func_name:
            disasm = dump_function_details(ea)
            if disasm:
                disasm_dic[name] = disasm
                print(name, 'done')
            else:
                print('Skip', name, 'less than five basic blocks')
else:
    func_cnt = 0
    for ea in Functions():
        name = get_func_name(ea)
        disasm = dump_function_details(ea)
        if disasm:
            disasm_dic[name] = disasm
            func_cnt += 1
    disasm_dic['num'] = func_cnt
    print(func_cnt, 'done')

disasm_json = json.dumps(disasm_dic)
with open('../output/' + file_name + '_disasm.json', 'w') as f:
    f.write(disasm_json)