import os
import json
from tlsh import hash
from hashlib import md5

pkg_name = 'curl'
pkg_ver = '8.0.1'
fw = 'tp'
ver = '26'

dir_raw = 'disasm_raw/' + fw + '-' + ver + '/' + pkg_name +'/'
dir_hash = 'disasm_hash/' + fw + '-' + ver + '/' + pkg_name + '/'
if not os.path.isdir(dir_hash):
    os.makedirs(dir_hash)

def sanitize_arm(disasm_dic):
    hash_dic = {}

    # for each function
    for key_func, value_func in disasm_dic.items():
        disasm_norm = ''
        bb_hash = {}
        # for each basic_block
        for key_bb, value_bb in value_func.items():
            bb_disasm = value_bb['disasm']
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
            bb_hash[key_bb] = md5(bb_disasm_norm.encode()).hexdigest()

            disasm_norm += bb_disasm_norm                             # type: str
            
        hash_dic[key_func] = {
            'func_hash': hash(disasm_norm.encode()),
            'bb_hash': bb_hash 
        }

    return hash_dic


def sanitize_x86(disasm_dic):
    hash_dic = {}

    # for each function
    for key_func, value_func in disasm_dic.items():
        disasm_norm = ''
        bb_hash = dict()
        # for each basic block
        for key_bb, value_bb in value_func.items():
            bb_disasm = value_bb['disasm']
            bb_disasm_norm = []
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
                    
                bb_disasm_norm += ins_disasm + ['\n']                 # type: list

            bb_disasm_norm = ''.join(op for op in bb_disasm_norm)     # type: str
            bb_hash[key_bb] = md5(bb_disasm_norm.encode()).hexdigest()

            disasm_norm += bb_disasm_norm                             # type: str
                
        hash_dic[key_func] = {
            'func_hash': hash(disasm_norm.encode()),
            'bb_hash': bb_hash,
        }

    return hash_dic


for file_name in os.listdir(dir_raw):

    if 'fw' not in file_name and pkg_ver not in file_name:
        continue

    hash_dic = {}

    print(file_name)

    with open(dir_raw + file_name, 'r') as f:
        contents_j = json.load(f)

    arch = contents_j['arch']
    del contents_j['arch']
    
    if 'fw' in file_name:
        num = contents_j['num']
        del contents_j['num']

    if arch == 'arm':
        hash_dic = sanitize_arm(contents_j)
    else:
        hash_dic = sanitize_x86(contents_j)

    if 'fw' in file_name:
        hash_dic['num'] = num

    hash_json = json.dumps(hash_dic)
    with open(dir_hash + file_name.split('_')[0] + '_hash.json', 'w') as f:
        f.write(hash_json)