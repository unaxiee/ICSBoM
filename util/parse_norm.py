from tlsh import hash
from hashlib import md5


def sanitize_arm_for_norm(disasm_dic):
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


def sanitize_x86_for_norm(disasm_dic):
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
