import networkx as nx
import editdistance
import csv
from math import *
import json
import os
from util import config
import time


def read_func_info(ven, pkg, lib, function_name, version, compiler):
	input_path = 'disasm/disasm_norm/' + ven + '/' + pkg + '/' + lib + '_' + version + '_norm.json'
	if compiler != '':
		input_path = 'disasm/disasm_norm/' + ven + '/' + pkg + '/' + lib + '_' + version + '_' + compiler + '_norm.json'
	func = None
	try:
		with open(input_path, 'r') as input:
			lib_j = json.load(input)
			if function_name in lib_j.keys():
				func = lib_j[function_name]
	except IOError as e:
		return None
	return func


def load_target_func(ven, fw, ver, pkg, lib, function_name):
	target_version = 'fw_' + fw + '_' + ver
	target_func = read_func_info(ven, pkg, lib, function_name, target_version, '')
	if not target_func:
		return None
	target_func = preprocess_func(target_func)
	return target_func


def get_bb_by_address(address, func):
	for key_bb, value_bb in func.items():
		if key_bb == address:
			return value_bb
	return None


def preprocess_func(func):
	for key_bb, value_bb in func.items():
		pred_disam_list = []
		for pred in value_bb['preds']:
			bb = get_bb_by_address(str(pred), func)
			if bb:
				pred_disam_list.append(bb['disasm'])
		succ_disam_list = []
		for succ in value_bb['succs']:
			bb = get_bb_by_address(str(succ), func)
			if bb:
				succ_disam_list.append(bb['disasm'])
		func[key_bb]['neighbor_disasm_list'] = [pred_disam_list, succ_disam_list]
	return func


def update_map(map, key, value, index):
	if index == 0:
		if not key in map:
			map[key] = [[],[]]
	elif index == 1:
		map[key][0].append(value)   # value: dict, {bb_key: bb_neighbor_disasm_list}
	elif index == 2:
		map[key][1].append(value)
	return map


def match_two_funcs(func1, func2):
	map = {}
	for key_bb_1, value_bb_1 in func1.items():
		update_map(map, value_bb_1['hash'], None, 0)
		update_map(map, value_bb_1['hash'], {key_bb_1: value_bb_1['neighbor_disasm_list']}, 1)
	for key_bb_2, value_bb_2 in func2.items():
		update_map(map, value_bb_2['hash'], None, 0)
		update_map(map, value_bb_2['hash'], {key_bb_2: value_bb_2['neighbor_disasm_list']}, 2)
	return map


def cal_score_trace(trace0, trace1):
	len0 = len(trace0)
	len1 = len(trace1)
	len_max = max(len0, len1)

	dist = editdistance.eval(trace0 , trace1)   # instruction disasm
	try:
		score = float(len_max - dist) / float(len_max)
	except ZeroDivisionError:
		return 0
	else:
		return score


def cal_score_traceset(traceset0, traceset1):
	len0 = len(traceset0)
	len1 = len(traceset1)
	score_p1 = 1.0 / (abs(len0 - len1) + 1)
	score_p2 = 0

	if len0 < len1:
		total_score = 0
		for trace1 in traceset1:
			score_max = 0
			for trace0 in traceset0:
				score = cal_score_trace(trace0, trace1)   # one pred / succ bb
				if score > score_max:
					score_max = score
			total_score += score_max
		score_p2 = float(total_score) / len1
	else:
		total_score = 0
		for trace0 in traceset0:
			score_max = 0
			for trace1 in traceset1:
				score = cal_score_trace(trace0, trace1)
				if score > score_max:
					score_max = score
			total_score += score_max
		score_p2 = float(total_score) / len0
	
	score_final = score_p1 * score_p2
	
	return score_final


def cal_score_bb(bb0, bb1):
	pred_score = 0
	succ_score = 0
	
	key_bb0 = list(bb0.keys())[0]
	key_bb1 = list(bb1.keys())[0]

	if len(bb0[key_bb0][0]) == 0 and len(bb1[key_bb1][0]) == 0:
		pred_score = 1
	elif len(bb0[key_bb0][0]) == 0 or len(bb1[key_bb1][0]) == 0:
		pred_score = 0
	else:
		pred_score = cal_score_traceset(bb0[key_bb0][0], bb1[key_bb1][0])   # all pred bbs

	if len(bb0[key_bb0][1]) == 0 and len(bb1[key_bb1][1]) == 0:
		succ_score = 1
	elif len(bb0[key_bb0][1]) == 0 or len(bb1[key_bb1][1]) == 0:
		succ_score = 0
	else:
		succ_score = cal_score_traceset(bb0[key_bb0][1], bb1[key_bb1][1])   # all succ bbs

	score_final = (pred_score + succ_score) / 2	
	return score_final


def handle_unmatched(hash):
	final_return = [[],[]]

	len1 = len(hash[0])   # number of bbs from func_list_1
	len2 = len(hash[1])   # number of bbs from func_list_2

	score_map = []
	for item1 in hash[0]:   # basic block from func_list_1
		score_row = []
		for item2 in hash[1]:   # basic block from func_list_2
			tmp_score = cal_score_bb(item1, item2)
			score_row.append(tmp_score)
		score_map.append(score_row)

	len_min = min(len1, len2)
	
	list1 = []
	list2 = []
	for x in range(len_min):
		max_score = 0
		index_row = 0
		index_col = 0
		for i in range(len(hash[0])):
			for j in range(len(hash[1])):
				if score_map[i][j] > max_score:
					max_score = score_map[i][j]
					index_row = i
					index_col = j

		for i in range(len(hash[0])):
			score_map[i][index_col] = -1
		for j in range(len(hash[1])):
			score_map[index_row][j] = -1

		list1.append(index_row)
		list2.append(index_col)

	if len1 < len2:
		rest_set = set(range(0, len2)) - set(list2)
		for idx in rest_set:
			final_return[1].append(list(hash[1][idx].keys())[0])   # return only key_bb
	else:
		rest_set = set(range(0, len1)) - set(list1)
		for idx in rest_set:
			final_return[0].append(list(hash[0][idx].keys())[0])

	return final_return


def get_diff_bbs(map):
	func1_bb_list = []
	func2_bb_list = []
	for k in map.keys():
		hash = map[k]
		
		if len(hash[0]) == len(hash[1]):   # equal number
			continue
		elif len(hash[0]) == 0:   # only appear in the first function
			for item in hash[1]:
				func2_bb_list.append(list(item.keys())[0])
		elif len(hash[1]) == 0:   # only appear in the second function
			for item in hash[0]:
				func1_bb_list.append(list(item.keys())[0])
		else:
			result = handle_unmatched(hash)   # appear in both functions
			if len(result[0]) > 0:
				func1_bb_list.extend(result[0])
			if len(result[1]) > 0:
				func2_bb_list.extend(result[1])

	func1_bb_list = list(set(func1_bb_list))
	func2_bb_list = list(set(func2_bb_list))
	return [func1_bb_list, func2_bb_list]


def bb_list_to_bb_rela_dict(address_list, func):
	bb_dict = dict()
	for add in address_list:
		bb = get_bb_by_address(add, func)
		if bb:
			pred_list = []
			for pred in bb['preds']:
				pred_list.append(str(pred))
			succ_list = []
			for succ in bb['succs']:
				succ_list.append(str(succ))
			bb_dict[add] = [pred_list, succ_list]

	return bb_dict


def build_trace_graph(bb_key_diff_list, bb_key_sur_list, func):
	# bb_key_list = bb_key_diff_list + bb_key_sur_list
	bb_key_list = bb_key_diff_list
	bb_key_rela_dict = bb_list_to_bb_rela_dict(bb_key_list, func)
	G = nx.DiGraph()
	for bb1 in bb_key_list:
		# if bb1 not in bb_key_rela_dict.keys():
		# 	continue
		G.add_node(bb1)
		for bb2 in bb_key_list:
			if bb2 in bb_key_rela_dict[bb1][0]:   # pred bb
				G.add_edge(bb2, bb1)
			if bb2 in bb_key_rela_dict[bb1][1]:   # succ bb
				G.add_edge(bb1, bb2)
	
	node_path = []
	for node in G.nodes():
		node_path.append([node])
	if len(G.nodes()) > 100:
		print('node num:', len(G.nodes()), 'trace num:', len(node_path))
		return [True, node_path]
	cnt = len(node_path)
	
	roots = (v for v, d in G.in_degree() if d == 0)
	root_list = []
	for root in roots:
		root_list.append(root)
	leaves = (v for v, d in G.out_degree() if d == 0)
	leaf_list = []
	for leaf in leaves:
		leaf_list.append(leaf)

	trace_path = []
	for root in root_list:
		for leaf in leaf_list:
			root_leaf_path = nx.all_simple_paths(G, root, leaf)
			if root_leaf_path:
				for path in root_leaf_path:
					# for bb in path:
					# 	if bb in bb_key_sur_list:
					trace_path.append(path)
					cnt += 1
							# break
					if cnt > 10000:
						print('node num:', len(G.nodes()), 'trace num:', len(node_path))
						return [True, node_path]
	all_path = node_path + trace_path
	print('node num:', len(G.nodes()), 'trace num:', len(all_path))
	return [False, all_path]


def get_instr_list(func, trace_in_list):
	instr_list = []
	for trace in trace_in_list:
		instr_list_per_bb = []
		for add in trace:
			bb = get_bb_by_address(add, func)
			if bb:
				instr_list_per_bb.extend(bb['disasm'])
		if len(instr_list_per_bb) != 0:
			instr_list.append(instr_list_per_bb)
	return instr_list


def matching(vp_vpt, vp_function, tar_vpt, tar_function):
	mul = len(vp_vpt) * len(tar_vpt)
	threshold = 1000000
	if (mul > threshold):
		return [False, threshold / mul]
	
	source_trace_list = get_instr_list(tar_function, tar_vpt)
	match_trace_list = get_instr_list(vp_function, vp_vpt)
	
	score_1 = 0
	for item1 in source_trace_list:
		max_score = 0
		len1 = len(item1)
		for item2 in match_trace_list:
			len2 = len(item2)
			len_max = max(len1, len2)
			dist = editdistance.eval(item1, item2)
			value = float(len_max - dist) / float(len_max)
			if value > max_score:
				max_score = value
		score_1 += max_score
	score_1 /= len(source_trace_list)

	# score_2 = 0
	# for item1 in match_trace_list:
	# 	max_score = 0
	# 	len1 = len(item1)
	# 	for item2 in source_trace_list:
	# 		len2 = len(item2)
	# 		len_max = max(len1, len2)
	# 		dist = editdistance.eval(item1, item2)
	# 		value = float(len_max - dist) / float(len_max)
	# 		if value > max_score:
	# 			max_score = value
	# 	score_2 += max_score
	# score_2 /= len(match_trace_list)
	score_2 = score_1

	return [True, (score_1 + score_2) / 2]


def find_surruding(bb_address_list, func):
	result_list = set()
	for key_bb, value_bb in func.items():
		if key_bb in bb_address_list:
			for pred in value_bb['preds']:
				result_list.add(str(pred))
			for succ in value_bb['succs']:
				result_list.add(str(succ))
	return_re = result_list - set(bb_address_list)
	return list(return_re)


def match_decision(ven, fw, ver, pkg, lib, ref_func_name, vul_version, patch_version, tar_func_name, compiler):
	vul_flag = True
	vul_func = read_func_info(ven, pkg, lib, ref_func_name, vul_version, compiler)
	if not vul_func:
		vul_flag = False
	else:
		vul_func = preprocess_func(vul_func)	# add neighbor_disasm

	patch_flag = True
	patch_func = read_func_info(ven, pkg, lib, ref_func_name, patch_version, compiler)
	if not patch_func:
		patch_flag = False
	else:
		patch_func = preprocess_func(patch_func)	# add neighbor_disasm

	target_func = load_target_func(ven, fw, ver, pkg, lib, tar_func_name)

	if not (vul_flag and patch_flag):
		if not vul_flag and not patch_flag:
			print('no vulnerable and patched version')
			return ['E no vulnerable and patched version']
		elif not vul_flag:
			if not target_func:
				return ['V function only appears in patched version']
			else:
				return ['P function appears in target and patched version but not in vulnerable']
		# not practical for removed function
		else:
			if not target_func:
				return ['P function only appears in vulnerable version']
			else:
				return ['V function appears in target and vulnerable version but not in patched']
	
	if not target_func:
		print('no target function')
		return ['E no target function']

	v_to_p = match_two_funcs(vul_func, patch_func)
	diff_v_to_p = get_diff_bbs(v_to_p)   # return key of different bbs
	if len(diff_v_to_p[0]) == 0 and len(diff_v_to_p[1]) == 0:
		return ['NA VP no diff']
	print('vul-patch', len(diff_v_to_p[0]), '/', len(diff_v_to_p[1]))

	v_to_t = match_two_funcs(vul_func, target_func)   # vul-tar map
	diff_v_to_t = get_diff_bbs(v_to_t)
	if len(diff_v_to_t[0]) == 0 and len(diff_v_to_t[1]) == 0:
		same_v = True
	else:
		same_v = False
	
	p_to_t = match_two_funcs(patch_func, target_func) # patch-tar map
	diff_p_to_t = get_diff_bbs(p_to_t)
	if len(diff_p_to_t[0]) == 0 and len(diff_p_to_t[1]) == 0:
		same_p = True
	else:
		same_p = False

	if same_v and same_p:
		return ['NA VT/PT no diff']
	elif same_p:
		return ['P']
	elif same_v:
		return ['V']

	s_vt_v = find_surruding(diff_v_to_t[0], vul_func)   # boundary basic blocks for unmatched bbs in vulnerable compared to target
	s_vt_t = find_surruding(diff_v_to_t[1], target_func)   # boundary basic blocks for unmatched bbs in target compared to vulnerable
	s_pt_p = find_surruding(diff_p_to_t[0], patch_func)   # boundary basic blocks for unmatched bbs in patched compared to target
	s_pt_t = find_surruding(diff_p_to_t[1], target_func)   # boundary basic blocks for unmatched bbs in target compared to patched

	vul_vt = build_trace_graph(diff_v_to_t[0], s_vt_v, vul_func)
	tar_vt = build_trace_graph(diff_v_to_t[1], s_vt_t, target_func)
	patch_pt = build_trace_graph(diff_p_to_t[0], s_pt_p, patch_func)
	tar_pt = build_trace_graph(diff_p_to_t[1], s_pt_t, target_func)
	
	# unfair comparision based on trace, compare # of diff bbs
	if (vul_vt[0] or patch_pt[0] or tar_vt[0] or tar_pt[0]) and not (vul_vt[0] and patch_pt[0] and tar_vt[0] and tar_pt[0]):
		print('PHASE1: diff bb #')
		diff_pt_sum = len(diff_p_to_t[0]) + len(diff_p_to_t[1])
		diff_vt_sum = len(diff_v_to_t[0]) + len(diff_v_to_t[1])
		if diff_vt_sum < diff_pt_sum:
			return ['V ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + '/' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		elif diff_pt_sum < diff_vt_sum:
			return ['P ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + '/' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		else:
			return ['NA cannot tell']
	vul_vt = vul_vt[1]
	tar_vt = tar_vt[1]
	patch_pt = patch_pt[1]
	tar_pt = tar_pt[1]
	
	if len(tar_vt) == 0 and len(tar_pt) == 0:
		return ['NA no trace for VT and PT']
	elif len(tar_vt) == 0:
		return ['V']
	elif len(tar_pt) == 0:
		return ['P']

	sim_vt = matching(vul_vt, vul_func, tar_vt, target_func)
	sim_pt = matching(patch_pt, patch_func, tar_pt, target_func)

	if sim_vt[0] and sim_pt[0]:
		print('PHASE2: trace value')
		sim_vt = sim_vt[1]
		sim_pt = sim_pt[1]
		if sim_vt > sim_pt:
			return ['V ' + str(sim_vt) + '/' + str(sim_pt)  + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		elif sim_vt < sim_pt:
			return ['P ' + str(sim_vt) + '/' + str(sim_pt)  + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		else:
			print('PHASE4: diff bb #')
			diff_pt_sum = len(diff_p_to_t[0]) + len(diff_p_to_t[1])
			diff_vt_sum = len(diff_v_to_t[0]) + len(diff_v_to_t[1])
			if diff_vt_sum < diff_pt_sum:
				return ['V ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + '/' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
			elif diff_pt_sum < diff_vt_sum:
				return ['P ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + '/' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
			else:
				return ['NA cannot tell']
			# return ['NA cannot tell']
	elif not sim_vt[0] and not sim_pt[0]:
		print('PHASE3: trace #')
		sim_vt = sim_vt[1]
		sim_pt = sim_pt[1]
		if sim_vt > sim_pt:
			return ['V ' + str(sim_vt) + '/' + str(sim_pt)  + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		elif sim_vt < sim_pt:
			return ['P ' + str(sim_vt) + '/' + str(sim_pt)  + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		else:	
			return ['NA cannot tell']
	else:
		print('PHASE4: diff bb #')
		diff_pt_sum = len(diff_p_to_t[0]) + len(diff_p_to_t[1])
		diff_vt_sum = len(diff_v_to_t[0]) + len(diff_v_to_t[1])
		if diff_vt_sum < diff_pt_sum:
			return ['V ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + '/' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		elif diff_pt_sum < diff_vt_sum:
			return ['P ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + '/' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ' vul-tar:' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ' patch-tar:' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		else:
			return ['NA cannot tell']


def detect_patch(ven, fw, ver, pkg, compiler):
	if not os.path.isfile('disasm/disasm_norm/' + ven + '/' + pkg + '/' + fw + '_' + ver + '_func_list.csv'):
		print('E no input func list for', fw, ver)
		return 0
	result_list = []
	cnt = 0
	with open('disasm/disasm_norm/' + ven + '/' + pkg + '/' + fw + '_' + ver + '_func_list.csv', 'r') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			lib = row[3]
			if lib == 'not found':
				print("[E] Cannot find affected function")
				continue

			tar_func_name = row[5]
			if tar_func_name == 'not match':
				print("[E] Cannot locate target function")
				continue

			CVE_id = row[0]
			vul_version = row[1]
			patch_version = row[2]
			ref_func_name = row[4]
			
			result_head = [CVE_id, ref_func_name, patch_version]
			print(result_head)
			
			decision = match_decision(ven, fw, ver, pkg, lib, ref_func_name, vul_version, patch_version, tar_func_name, compiler)
			print(decision)
			result_head.extend(decision)
			result_list.append(result_head)
			cnt += 1

	dir_output = 'output_patch_detection/' + pkg + '/'
	if not os.path.isdir(dir_output):
		os.makedirs(dir_output)
	
	file_output = dir_output + ven + '_' + fw + '_' + ver + '.json'
	if compiler != '':
		file_output = dir_output + ven + '_' + fw + '_' + ver + '_' + compiler + '.json'
	if os.path.isfile(file_output):
		os.remove(file_output)

	with open(file_output, 'a') as f:
		for result in result_list:
			json.dump(result, f)
			f.write('\n')
	
	return cnt
	

with open('util/fw_lib_list/' + config.ven + '.csv', 'r') as f:
    lines = f.readlines()
start = time.time()
cnt = 0
for line in lines:
    line = line[:-1].split(',')
    config.fw = line[1]
    config.fw_ver = line[2]
    config.lib = line[3]
    config.lib_ver = line[4]
    # if config.lib != config.test_lib:
    #     continue
    # if config.fw_ver != config.test_fw_ver:
    #     continue
    print(line)
    cnt += detect_patch(config.ven, config.fw, config.fw_ver, config.lib, config.test_compiler)
end = time.time()
print(cnt, end - start, (end - start) / cnt)