from tlsh import hash, diff
import json

dir = 'disasm_hash/'

with open(dir + 'src.json', 'r') as f:
    src_j = json.load(f)

with open(dir + 'fw.json', 'r') as f:
    fw_j = json.load(f)

for key, value in src_j.items():
    select = {
        'func': 'test',
        'diff': 1000,
        'size': 0
    }
    for key_can, value_can in fw_j.items():
        if value['size'] < value_can['size'] * 1.2 and value['size'] > value_can['size'] * 0.8:
            diff_tmp = diff(value['hash'], value_can['hash'])
            if diff_tmp < select['diff']:
                select['func'] = key_can
                select['diff'] = diff_tmp
                select['size'] = value_can['size']
            if key_can == key:
                print(diff_tmp)
    print(key, value['size'], select)