import os
import json
from tlsh import hash
from hashlib import md5

pkg_name = 'expat'

dir_raw = 'disasm_raw/' + pkg_name +'/'
dir_pd = 'disasm_norm/' + pkg_name + '/'

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