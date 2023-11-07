from idautils import *
from idaapi import *
import csv
import json


def get_func_for_src():
    func_name = []
    with open('func_list_src.csv', 'r') as f:
        r = csv.reader(f, delimiter=',')
        for row in r:
            for item in row:
                func_name.append(item)
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


disasm_dic = {}
file_name = get_root_filename()

if 'src' in file_name:
    func_name = get_func_for_src()
    for ea in Functions():
        name = get_func_name(ea)
        if name in func_name:
            disasm_dic[name] = dump_function_details(ea)
            print(name, 'done')
else:
    func_cnt = 0
    for ea in Functions():
        name = get_func_name(ea)
        disasm = dump_function_details(ea)
        if len(disasm) > 0:
            disasm_dic[name] = disasm
            func_cnt += 1
    print(func_cnt, 'done')

disasm_json = json.dumps(disasm_dic)
with open('output/' + file_name + '_disasm.json', 'w') as f:
    f.write(disasm_json)