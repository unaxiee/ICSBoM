from tlsh import diff
import json

dir = 'disasm_hash/'

with open(dir + 'src_hash.json', 'r') as f:
    src_j = json.load(f)

with open(dir + 'fw_hash.json', 'r') as f:
    fw_j = json.load(f)

for key, value in src_j.items():
    print(key, len(value['bb_hash']))
    select = {
        'func': 'test',
        'diff': 1000,
        'bb_hash': []
    }
    for key_can, value_can in fw_j.items():
        # if value_can['size'] < value['size'] + 10 and value_can['size'] > value['size'] - 10:
        diff_tmp = diff(value['func_hash'], value_can['func_hash'])

        if key_can == key:
            cnt = 0
            for bb_hash in value['bb_hash']:
                for bb_hash_can in value_can['bb_hash']:
                    if bb_hash == bb_hash_can:
                        cnt += 1
            print(key_can, cnt, diff_tmp)
        
        if diff_tmp < select['diff']:
            select['func'] = key_can
            select['diff'] = diff_tmp
            select['bb_hash'] = value_can['bb_hash']

    cnt = 0
    for bb_hash in value['bb_hash']:
        for bb_hash_can in select['bb_hash']:
            if bb_hash == bb_hash_can:
                cnt += 1

    print(select['func'], cnt, select['diff'])