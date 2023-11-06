import os
import json
from tlsh import hash

dir_raw = 'disasm_raw/'
dir_norm = 'disasm_hash/'

for file_name in os.listdir(dir_raw):

    hash_dic = {}

    if '.json' not in file_name:
        continue

    with open(dir_raw + file_name, 'r') as f:
        contents_j = json.load(f)

    for key, value in contents_j.items():
        disasm = value['disasm']
        disasm_norm = []
        for bb_disasm in disasm:
            for ins_disasm in bb_disasm:
                if ';' in ins_disasm:
                    ins_disasm = ins_disasm[:ins_disasm.index(';')]
                ins_disasm = ins_disasm.replace(',', '').split()
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
                disasm_norm = disasm_norm + ins_disasm
        disasm_norm = ''.join(op for op in disasm_norm)
        hash_dic[key] = {
            'size': value['size'],
            'hash': hash(disasm_norm.encode())
        }

    hash_json = json.dumps(hash_dic)
    with open(dir_norm + file_name, 'w') as f:
        f.write(hash_json)