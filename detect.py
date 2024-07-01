import networkx as nx
import editdistance
import csv
from math import *
import json
import os
from util import config


def read_func_info(ven, pkg, lib, function_name, version):
	# input_path = 'disasm/disasm_norm/' + fw + '/' + ver + '/' + pkg + '/' + lib + '-' + version + '_norm.json'
	input_path = 'disasm/disasm_norm/' + ven + '/' + pkg + '/' + lib + '_' + version + '_norm.json'
	func = None
	try:
		with open(input_path, 'r') as input:
			lib_j = json.load(input)
			if function_name in lib_j.keys():
				func = lib_j[function_name]
	except IOError as e:
		return None
	return func


def get_bb_by_address(address, func):
	for key_bb, value_bb in func.items():
		if key_bb == address:
			return [value_bb['disasm'], value_bb['preds'], value_bb['succs']]
	return None


def preprocess_func(func):
	for key_bb, value_bb in func.items():
		pred_disam_list = []
		for pred in value_bb['preds']:
			tmp_bb = get_bb_by_address(str(pred), func)
			if tmp_bb:
				pred_disam_list.append(tmp_bb[0])   # bb['disasm']
		succ_disam_list = []
		for succ in value_bb['succs']:
			tmp_bb = get_bb_by_address(str(succ), func)
			if tmp_bb:
				succ_disam_list.append(tmp_bb[0])
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

	if len(bb0[key_bb0][0]) and len(bb1[key_bb1][0]) == 0:
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


def handle_unmatched(record):
	final_return = [[],[]]

	len0 = len(record[0])   # number of bbs from func_list_0
	len1 = len(record[1])   # number of bbs from func_list_1

	score_map = []
	for item0 in record[0]:   # basic block from func_list_0
		tmp_record = []
		for item1 in record[1]:   # basic block from func_list_1
			tmp_score = cal_score_bb(item0, item1)
			tmp_record.append(tmp_score)
		score_map.append(tmp_record)

	len_min = min(len0, len1)
	
	list0 = []
	list1 = []
	for x in range(len_min):
		max_score = 0
		index_row = 0
		index_col = 0
		for i in range(len(record[0])):
			for j in range(len(record[1])):
				if score_map[i][j] > max_score:
					max_score = score_map[i][j]
					index_row = i
					index_col = j

		for i in range(len(record[0])):
			score_map[i][index_col] = -1
		for j in range(len(record[1])):
			score_map[index_row][j] = -1

		list0.append(index_row)
		list1.append(index_col)

	if len0 < len1:
		rest_set = set(range(0, len1)) - set(list1)
		for item in rest_set:
			final_return[1].append(list(record[1][item].keys())[0])   # return only key_bb
	else:
		rest_set = set(range(0, len0)) - set(list0)
		for item in rest_set:
			final_return[0].append(list(record[0][item].keys())[0])

	return final_return


def get_diff_bbs(map):
	func1_bb_list = []
	func2_bb_list = []
	for k in map.keys():
		record = map[k]
		
		if len(record[0]) == len(record[1]):   # equal number
			continue
		elif len(record[0]) == 0:   # only appear in one function
			for item in record[1]:
				for key in item.keys():
					func2_bb_list.append(key)
		elif len(record[1]) == 0:   # only appear in one function
			for item in record[0]:
				for key in item.keys():
					func1_bb_list.append(key)
		else:
			result = handle_unmatched(record)   # appear in both functions
			if len(result[0]) > 0:
				func1_bb_list.extend(result[0])
			if len(result[1]) > 0:
				func2_bb_list.extend(result[1])

	func1_bb_list = list(set(func1_bb_list))
	func2_bb_list = list(set(func2_bb_list))
	return [func1_bb_list, func2_bb_list]


def extract_sig(ven, fw, ver, pkg, lib, function_name, vul_version, patch_version):
	vul_flag = True
	vul_func = read_func_info(ven, pkg, lib, function_name, vul_version)
	if not vul_func:
		vul_flag = False
	else:
		vul_func = preprocess_func(vul_func)	# add neighbor_disasm

	patch_flag = True
	patch_func = read_func_info(ven, pkg, lib, function_name, patch_version)
	if not patch_func:
		patch_flag = False
	else:
		patch_func = preprocess_func(patch_func)	# add neighbor_disasm

	if vul_flag and patch_flag:
		map = match_two_funcs(vul_func, patch_func)
		diff = get_diff_bbs(map)   # return key of different bbs
		return [vul_func, patch_func, diff]
	else:
		return [vul_flag, patch_flag]


def load_target_func(ven, fw, ver, pkg, lib, function_name):
	target_version = 'fw_' + fw + '_' + ver
	target_func = read_func_info(ven, pkg, lib, function_name, target_version)
	if not target_func:
		return None
	target_func = preprocess_func(target_func)
	return target_func


def isEmpty(diff):
	return len(diff[0]) == 0 and len(diff[1]) == 0


def add_list_to_bb_list(address_list, func):
	bb_list = dict()
	for add in address_list:
		bb = get_bb_by_address(add, func)
		if bb:
			bb_list[add] = [bb[1], bb[2]]
	return bb_list


def build_trace_graph_v2(bb_add_list_changed, bb_add_list_root, func):
	bb_add_list_in_graph = list(set(bb_add_list_changed).union(set(bb_add_list_root)))
	bb_list_in_graph = add_list_to_bb_list(bb_add_list_in_graph, func)
	G = nx.DiGraph()
	for bb1 in bb_add_list_in_graph:
		if bb1 not in bb_list_in_graph.keys():
			continue
		G.add_node(bb1)
		for bb2 in bb_add_list_in_graph:
			if bb2 in bb_list_in_graph[bb1][0]:   # pred bb
				G.add_edge(bb2, bb1)
			if bb2 in bb_list_in_graph[bb1][1]:   # succ bb
				G.add_edge(bb1, bb2)
	
	if len(G.nodes()) > 300:
		print('too many blocks')
		return -1

	roots = (v for v, d in G.in_degree() if d == 0)
	root_list = []
	for root in roots:
		root_list.append(root)

	leaves = (v for v, d in G.out_degree() if d == 0)
	leaf_list = []
	for leaf in leaves:
		leaf_list.append(leaf)

	all_paths = []
	cnt = 0
	for root in root_list:
		for leaf in leaf_list:
			if root == leaf and (root in bb_add_list_root or len(G.nodes()) == 1):
				all_paths.extend([[root]])
				cnt += 1

			paths = nx.all_simple_paths(G, root, leaf)
			if paths:
				ppath = []
				for path in paths:
					for b in path:
						if b in bb_add_list_root:
							ppath.append(path)
							cnt += 1
							break
					if cnt >= 50000:
						print('too many trace')
						return -1
				all_paths.extend(ppath)

	return all_paths


def get_instr_list(func, trace_in_list):
	instr_list = []
	for trace in trace_in_list:
		instr_list_list_bb = []
		for bb in trace:
			for key_bb, value_bb in func.items():
				if key_bb == bb:
					instr_list_list_bb.extend(value_bb['disasm'])
					break
		instr_list.append(instr_list_list_bb)
	return instr_list


def matching_v2(source_trace_list, match_trace_list):
	mul = len(source_trace_list) * len(match_trace_list)
	len_thresh = 5000000
	if (mul > len_thresh):
		return len_thresh / mul
	
	trace_count = len(source_trace_list)
	total_score = 0
	for item1 in source_trace_list:
		max_score = 0
		len1 = len(item1)
		for item2 in match_trace_list:
			len2 = len(item2)
			lenn = max(len1,len2)

			dist = editdistance.eval(item1 , item2)
			value = float(lenn - dist) / float(lenn)
			if value > max_score:
				max_score = value
		total_score += max_score

	if trace_count > 0:
		return float(total_score) / float(trace_count)
	else:
		return -1


def find_surruding(bb_address_list, func):
	result_list = []
	for key_bb, value_bb in func.items():
		if key_bb in bb_address_list:
			result_list.extend(value_bb['preds'])
			result_list.extend(value_bb['succs'])
	return_re = set(result_list) - set(bb_address_list)
	return_re = list(return_re)
	return return_re


def match_decision(target_func, sig):
	vul_func = sig[0]
	patch_func = sig[1]
	diff = sig[2]

	if isEmpty(diff):
		return ['NA VP no diff']
	# print('vul-patch', len(diff[0]), len(diff[1]))

	v_to_t = match_two_funcs(vul_func, target_func)   # vul-tar map
	diff_v_to_t = get_diff_bbs(v_to_t)
	
	p_to_t = match_two_funcs(patch_func, target_func) # patch-tar map
	diff_p_to_t = get_diff_bbs(p_to_t)
	
	same_v = isEmpty(diff_v_to_t)
	same_p = isEmpty(diff_p_to_t)

	if same_v and same_p:
		return ['NA VT/PT no diff']
	elif same_p:
		return ['P']
	elif same_v:
		return ['V']
	
	# print('vul-target', len(diff_v_to_t[0]), len(diff_v_to_t[1]))
	# print('patch-target', len(diff_p_to_t[0]), len(diff_p_to_t[1]))

	s_vt_v = find_surruding(diff_v_to_t[0], vul_func)   # boundary basic blocks for unmatched bbs in vulnerable compared to target
	s_vt_t = find_surruding(diff_v_to_t[1], target_func)   # boundary basic blocks for unmatched bbs in target compared to vulnerable
	s_pt_p = find_surruding(diff_p_to_t[0], patch_func)   # boundary basic blocks for unmatched bbs in patched compared to target
	s_pt_t = find_surruding(diff_p_to_t[1], target_func)   # boundary basic blocks for unmatched bbs in target compared to patched

	print('build vul_vt trace based on', len(diff_v_to_t[0]), 'basic blocks')
	vul_vt = build_trace_graph_v2(diff_v_to_t[0], s_vt_v, vul_func)
	print('build tar_vt trace based on', len(diff_v_to_t[1]), 'basic blocks')
	tar_vt = build_trace_graph_v2(diff_v_to_t[1], s_vt_t, target_func)
	print('build patch_pt trace based on', len(diff_p_to_t[0]), 'basic blocks')
	patch_pt = build_trace_graph_v2(diff_p_to_t[0], s_pt_p, patch_func)
	print('build tar_pt trace based on', len(diff_v_to_t[1]), 'basic blocks')
	tar_pt = build_trace_graph_v2(diff_p_to_t[1], s_pt_t, target_func)
	
	if vul_vt == -1 or patch_pt == -1 or tar_vt == -1 or tar_pt == -1:
		diff_pt_sum = len(diff_p_to_t[0]) + len(diff_p_to_t[1])
		diff_vt_sum = len(diff_v_to_t[0]) + len(diff_v_to_t[1])
		if diff_vt_sum < diff_pt_sum:
			return ['V ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + ' / ' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		elif diff_pt_sum < diff_vt_sum:
			return ['P ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + ' / ' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
		else:
			return ['NA cannot tell']
	
	if len(tar_vt) == 0 and len(tar_pt) == 0:
		return ['NA no trace for VT or PT']
	elif len(tar_vt) == 0:
		return ['V']
	elif len(tar_pt) == 0:
		return ['P']

	trace_list_vul_vt = get_instr_list(vul_func, vul_vt)
	trace_list_tar_vt = get_instr_list(target_func, tar_vt)
	trace_list_patch_pt = get_instr_list(patch_func, patch_pt)
	trace_list_tar_pt = get_instr_list(target_func, tar_pt)
	
	s_vt = matching_v2(trace_list_vul_vt, trace_list_tar_vt)
	s_pt = matching_v2(trace_list_patch_pt, trace_list_tar_pt)

	# if abs(s_vt - s_pt) > 0.1:
	if s_vt > s_pt:
		return ['V ' + str(s_vt) + '/' + str(s_pt)  + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
	elif s_vt < s_pt:
		return ['P ' + str(s_vt) + '/' + str(s_pt)  + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
	else:
		return ['NA cannot tell']
	# else:
	# 	s_vp_v = find_surruding(diff[0], vul_func)
	# 	s_vp_p = find_surruding(diff[1], patch_func)
	# 	vul_vp = build_trace_graph_v2(diff[0], s_vp_v, vul_func)
	# 	patch_vp = build_trace_graph_v2(diff[1], s_vp_p, patch_func)
	# 	if vul_vp == -1 or patch_vp == -1:
	# 		return ['NA too much diff']
	# 	trace_list_vul_vp = get_instr_list(vul_func, vul_vp)
	# 	trace_list_patch_vp = get_instr_list(patch_func, patch_vp)
	# 	if len(trace_list_vul_vp) == 0 or len(trace_list_patch_vp) == 0:
	# 		return ['NA cannot tell']
	# 	s_vt_n = matching_v2(trace_list_vul_vp, trace_list_tar_pt)
	# 	s_pt_n = matching_v2(trace_list_patch_vp, trace_list_tar_vt)
	# 	if abs(s_vt_n - s_pt_n) > 0.1:
	# 		if s_vt_n > s_pt_n:
	# 			return ['V ' + str(s_vt_n) + '/' + str(s_pt_n)  + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
	# 		elif s_vt_n < s_pt_n:
	# 			return ['P ' + str(s_vt_n) + '/' + str(s_pt_n)  + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
	# 		else:
	# 			return ['NA cannot tell']
	# 	else:
	# 		diff_pt_sum = len(diff_p_to_t[0]) + len(diff_p_to_t[1])
	# 		diff_vt_sum = len(diff_v_to_t[0]) + len(diff_v_to_t[1])
	# 		if diff_vt_sum < diff_pt_sum:
	# 			return ['V ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + ' / ' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
	# 		elif diff_pt_sum < diff_vt_sum:
	# 			return ['P ' + str(diff_pt_sum / (diff_vt_sum + diff_pt_sum)) + ' / ' + str(diff_vt_sum / (diff_vt_sum + diff_pt_sum)) + ', vul-tar: ' + str(len(diff_v_to_t[0])) + '/' + str(len(diff_v_to_t[1])) + ', patch-tar: ' + str(len(diff_p_to_t[0])) + '/' + str(len(diff_p_to_t[1]))]
	# 		else:
	# 			return ['NA cannot tell']


def run_one_exp(ven, fw, ver, pkg, lib, function_name, vul_version, patch_version, tar_func_name):
	
	sig = extract_sig(ven, fw, ver, pkg, lib, function_name, vul_version, patch_version)   # sig includes [vul_func, patch_func, diff]

	target_func = load_target_func(ven, fw, ver, pkg, lib, tar_func_name)

	if len(sig) == 2:
		if not sig[0] and not sig[1]:
			print('no vulnerable and patched version')
			return ['E no vulnerable and patched version']
		elif not sig[0]:
			if not target_func:
				return ['V function only appears in patched version']
			else:
				return ['P function appears in target and patched version, but not in vulnerable']
		# not practical for removed function
		else:
			if not target_func:
				return ['P function only appears in vulnerable version']
			else:
				return ['V function appears in target and vulnerable version, but not in patched']
	
	if not target_func:
		print('no target function')
		return ['E no target function']
			
	decision = match_decision(target_func, sig)

	return decision


def detect_patch(ven, fw, ver, pkg):
	record_list = []
	# with open('disasm/disasm_norm/' + fw + '/' + ver + '/' + pkg +'/func_list.csv', 'r') as csvfile:
	with open('disasm/disasm_norm/' + ven + '/' + pkg + '/' + fw + '_' + ver + '_func_list.csv', 'r') as csvfile:
		r = csv.reader(csvfile, delimiter=',')
		for row in r:
			if len(row) == 6:
				func = row[4]
				func = func.replace("*","")
				func = func.strip()
				record_list.append([row[0], row[1], row[2], row[3], func, row[5]])
	print(len(record_list))

	result = []
	cnt = 0
	for record in record_list:
		lib = record[3]
		if lib == 'not found':
			print("[E] Cannot find affected function")
			continue

		tar_func_name = record[5]
		if tar_func_name == 'not match':
			print("[E] Cannot locate target function")
			continue

		CVE_id = record[0]
		vul_version = record[1]
		patch_version = record[2]
		function_name = record[4]
		
		result_head = [CVE_id, function_name, patch_version]
		print(result_head)
		
		decision = run_one_exp(ven, fw, ver, pkg, lib, function_name, vul_version, patch_version, tar_func_name)
		print(decision)
		if len(decision) > 0:
			result_head.extend(decision)
			result.append(result_head)
			if decision[0][0] != 'E':
				cnt += 1

	dir_output = 'output_patch_detection/' + pkg + '/'
	if not os.path.isdir(dir_output):
		os.makedirs(dir_output)
	
	file_output = dir_output + ven + '_' + fw + '_' + ver + '.json'
	if os.path.isfile(file_output):
		os.remove(file_output)

	with open(file_output, 'a') as f:
		for result_line in result:
			json.dump(result_line, f)
			f.write('\n')
	
	print(cnt)


if __name__ == '__main__':
	
	# arguments: firmware family, firmware version, package
	detect_patch(config.ven, config.fw, config.fw_ver, config.lib)