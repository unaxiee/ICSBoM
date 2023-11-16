import os
import json
from tlsh import hash
from hashlib import md5

dir_raw = 'disasm_raw/'
dir_norm = 'disasm_hash/'

lib_name = 'libssh2'

for file_name in os.listdir(dir_raw):

    hash_dic = {}

    if lib_name not in file_name:
        continue

    with open(dir_raw + file_name, 'r') as f:
        contents_j = json.load(f)

    for key, value in contents_j.items():
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

    hash_json = json.dumps(hash_dic)
    with open(dir_norm + file_name.split('_')[0] + '_hash.json', 'w') as f:
        f.write(hash_json)