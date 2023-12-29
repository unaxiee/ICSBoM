import os
import json
from tlsh import hash
from hashlib import md5

pkg_name = 'expat'

dir_raw = 'disasm_raw/' + pkg_name +'/'
dir_pd = 'disasm_pd/' + pkg_name + '/'

def sanitize_arm(disasm_dic):
    hash_dic = {}

    for key, value in disasm_dic.items():
        disasm_norm = ''
        bb_hash = []

        for bb_disasm in value:
            bb_disasm_norm = []

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

                bb_disasm_norm += ins_disasm + ['\n']                 # type: list

            bb_disasm_norm = ''.join(op for op in bb_disasm_norm)     # type: str
            # print(bb_disasm_norm)
            bb_hash.append(md5(bb_disasm_norm.encode()).hexdigest())

            disasm_norm += bb_disasm_norm                             # type: str
            
        hash_dic[key] = {
            'func_hash': hash(disasm_norm.encode()),
            'bb_hash': bb_hash 
        }

    return hash_dic


def sanitize_x86(disasm_dic):
    func_dic = {}

    # for each function
    for key_func, value_func in disasm_dic.items():
        disasm_norm = ''
        bb_dic = dict()
        # for each basic block
        for key, value in value_func.items():
            if key == 'preds':
                preds = value
            elif key == 'succs':
                succs = value
            else:
                bb_disasm_norm = []
                for ins_disasm in value:                              # type: str
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

                bb_dic[key] = bb_disasm_norm
                
        func_dic[key_func] = {
            'disasm': bb_dic,
            'preds': preds,
            'succs': succs
        }

    return func_dic


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