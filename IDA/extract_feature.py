from idautils import *
from idaapi import *
import csv
import json


def get_func_for_build():
    func_name = []
    with open('func_list.csv', 'r') as f:
        r = csv.reader(f, delimiter=',')
        for row in r:
            func_name.append(row[-1])
    return func_name

def dump_function_details(ea):
    disasm = []
    cnt = 0

    for bb in FlowChart(get_func(ea)):
        if bb.start_ea != bb.end_ea:
            bb_disasm = []
            for head in Heads(bb.start_ea, bb.end_ea):
                bb_disasm.append(GetDisasm(head))
            disasm.append(bb_disasm)
            cnt += 1

    if cnt > 5:
        return disasm
    else:
        return []


file_name = get_root_filename()

procname = get_inf_structure().procname.lower()
disasm_dic = {'arch': procname}

if 'build' in file_name:
    func_name = get_func_for_build()
    for ea in Functions():
        name = get_func_name(ea)
        if name in func_name:
            disasm = dump_function_details(ea)
            if len(disasm) > 0:
                disasm_dic[name] = disasm
                print(name, 'done')
            else:
                print('Skip', name, 'less than five basic blocks')
else:
    func_cnt = 0
    for ea in Functions():
        name = get_func_name(ea)
        disasm = dump_function_details(ea)
        if len(disasm) > 0:
            disasm_dic[name] = disasm
            func_cnt += 1
    disasm_dic['num'] = func_cnt
    print(func_cnt, 'done')

disasm_json = json.dumps(disasm_dic)
with open('../output/' + file_name + '_disasm.json', 'w') as f:
    f.write(disasm_json)