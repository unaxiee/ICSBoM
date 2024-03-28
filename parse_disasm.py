import os
import json
from tlsh import hash
from hashlib import md5
import csv

pkg_name = 'e2fsprogs'
pkg_ver = '1.43.8'
fw = 'ac500'
ver = 'hf5'

fw_ven_dic = {
    'pfc': 'wago',
    'cc': 'wago',
    'tp': 'wago',
    'iot2000': 'siemens',
    'ac500': 'abb'
}

dir_raw = 'disasm_raw/' + fw + '-' + ver + '/' + pkg_name +'/'
dir_pd = 'disasm_norm/' + fw + '-' + ver + '/' + pkg_name + '/'
if not os.path.isdir(dir_pd):
    os.makedirs(dir_pd)

def sanitize_arm(disasm_dic):
    # for each function
    for key_func, value_func in disasm_dic.items():
        
        # for each basic block
        for key_bb, value_bb in value_func.items():        
            bb_disasm_norm = []
            bb_disasm = value_bb['disasm']

            for ins_disasm in bb_disasm:                              # type: str
                if ';' in ins_disasm:
                    ins_disasm = ins_disasm[:ins_disasm.index(';')]

                ins_disasm = ins_disasm.replace(',', '').split()      # type: list
                
                for op in ins_disasm:
                    if op.startswith('#'):
                        ins_disasm[ins_disasm.index(op)] = 'imm'
                    elif op.startswith('loc'):
                        ins_disasm[ins_disasm.index(op)] = 'addr'
                    elif op.startswith('0x'):
                        ins_disasm[ins_disasm.index(op)] = 'addr'
                    elif '.W' in op:
                        ins_disasm[ins_disasm.index(op)] = op[:op.index('.W')]
                    elif '#' in op:
                        if ']' in op[op.index('#'):]:
                            op_new = op[:op.index('#')] + 'offs]'
                        else:
                            op_new = op[:op.index('#')] + 'offs'
                        ins_disasm[ins_disasm.index(op)] = op_new
                    elif '_' in op:
                        ins_disasm[ins_disasm.index(op)] = 'func'
                    elif op.startswith('=(a'):
                        ins_disasm[ins_disasm.index(op)] = 'func'
                    
                ins_disasm = ' '.join(ins_disasm)

                bb_disasm_norm.append(ins_disasm)               # type: list

            disasm_dic[key_func][key_bb]['disasm'] = bb_disasm_norm
            bb_disasm_norm_str = ''.join(ins for ins in bb_disasm_norm)
            disasm_dic[key_func][key_bb]['hash'] = md5(bb_disasm_norm_str.encode()).hexdigest()

    return disasm_dic


def sanitize_x86(disasm_dic):
    # for each function
    for key_func, value_func in disasm_dic.items():
        
        # for each basic block
        for key_bb, value_bb in value_func.items():
            bb_disasm_norm = []
            bb_disasm = value_bb['disasm']

            for ins_disasm in bb_disasm:                              # type: str
                if ';' in ins_disasm:
                    ins_disasm = ins_disasm[:ins_disasm.index(';')]

                ins_disasm = ins_disasm.replace(',', '').split()      # type: list

                for op in ins_disasm:
                    if op.endswith('h') and len(op)!=4:
                        ins_disasm[ins_disasm.index(op)] = 'imm'
                    elif len(op)==1 and op.isnumeric():
                        ins_disasm[ins_disasm.index(op)] = 'imm'
                    elif op.startswith('loc'):
                        ins_disasm[ins_disasm.index(op)] = 'addr'
                    elif '(' in op and ')' not in op:
                        op_new = op[:op.index('(')] + '(func'
                        ins_disasm[ins_disasm.index(op)] = op_new
                    elif '(' not in op and ')' in op:
                        op_new = 'imm' + op[op.index(')'):]
                        ins_disasm[ins_disasm.index(op)] = op_new
                    elif '+' in op and ']' in op:
                        op_new = op[:op.index('+')] + '+imm]'
                        ins_disasm[ins_disasm.index(op)] = op_new
                    elif '-' in op and ']' in op:
                        op_new = op[:op.index('-')] + '-imm]'
                        ins_disasm[ins_disasm.index(op)] = op_new
                    elif '_' in op:
                        ins_disasm[ins_disasm.index(op)] = 'func'
                
                ins_disasm = ' '.join(ins_disasm)
                    
                bb_disasm_norm.append(ins_disasm)                 # type: list

            disasm_dic[key_func][key_bb]['disasm'] = bb_disasm_norm
            bb_disasm_norm_str = ''.join(ins for ins in bb_disasm_norm)
            disasm_dic[key_func][key_bb]['hash'] = md5(bb_disasm_norm_str.encode()).hexdigest()

    return disasm_dic


for file_name in os.listdir(dir_raw):

    disasm_dic = {}

    print(file_name)

    with open(dir_raw + file_name, 'r') as f:
        contents_j = json.load(f)

    arch = contents_j['arch']
    del contents_j['arch']
    
    if 'fw' in file_name:
        num = contents_j['num']
        del contents_j['num']

    if arch == 'arm':
        disasm_dic = sanitize_arm(contents_j)
    else:
        disasm_dic = sanitize_x86(contents_j)

    if 'fw' in file_name:
        disasm_dic['num'] = num

    disasm_json = json.dumps(disasm_dic)
    with open(dir_pd + file_name.split('_')[0] + '_norm.json', 'w') as f:
        f.write(disasm_json)

dic_func_lib = {}
with open('util/func_lib/' + pkg_name + '/' + pkg_name + '_fw-' + fw + '-' + ver + '_func_lib.csv', 'r') as f_func_lib:
    reader_func_lib = csv.reader(f_func_lib)
    next(reader_func_lib, None)
    for func_lib in reader_func_lib:
        dic_func_lib[func_lib[0]] = [func_lib[1], func_lib[2]]
print(dic_func_lib)

with open('disasm_norm/' + fw + '-' + ver + '/' + pkg_name + '/func_list.csv', 'w') as f:
    writer = csv.writer(f)
    with open('IDA/func_list_' + fw_ven_dic[fw] + '/' + pkg_name + '_func_list.csv', 'r') as f_func_list:
        reader_func_list = csv.reader(f_func_list)
        for func_list in reader_func_list:
            writer.writerow([func_list[0], pkg_ver, func_list[1], dic_func_lib[func_list[2]][0], func_list[2], dic_func_lib[func_list[2]][1]])