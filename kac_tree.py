from kac import KAC
from binary_tree import Node as HashTree
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject
import math, itertools, pickle, time, random, csv
from sys import getsizeof

class KAC_Tree:
	def __init__(self, n, m, groupObj='SS512'):
		global group
		self.kac_layer = KAC(groupObj)
		group = self.kac_layer.group
		self.kac_size = n/m
		self.leaf_count = m
		#self.root_nodes = [HashTree(kac_layer.group.random(GT), self.KAC_to_range(i+1)['min'], self.KAC_to_range(i+1)['max']) for i in range(self.kac_size)]
		

	def setup(self):
		param = self.kac_layer.setup(self.kac_size)

		return param

	def keygen(self, param):
		key = self.kac_layer.keygen(param)
		# self.pk = keys['pk']
		# self.msk = keys['msk']
		# index begin from 1 instead of 0
		self.root_nodes = [None]
		self.root_nodes.extend([HashTree(self.kac_layer.group.random(GT), self.KAC_to_range(i+1)['min'], self.KAC_to_range(i+1)['max']) for i in xrange(self.kac_size)])
		return key
		#print self.kac_layer.keygen()
		# print self.root_nodes[1].data


	# def precompute_param_exp(self, param, msk):
	# 	param_exp = self.kac_layer.precompute_param_exp(param, msk)
	# 	return param_exp

	def encrypt(self, pk, param):
		# index begin from 1 instead of 0
		self.ct = [self.kac_layer.group.random(GT)]
		self.ct.extend([self.kac_layer.encrypt(pk, i+1, self.root_nodes[i+1].data, param) for i in xrange(self.kac_size)])
		return self.ct



	def aggregate(self, msk, param, min_val, max_val):
		KAC_index_range = self.range_to_KAC(min_val, max_val)
		# start <= i < end
		K_s = S = None
		if (KAC_index_range is not None):
			S = [i for i in xrange(KAC_index_range['min'],KAC_index_range['max']+1)]
			K_s = self.kac_layer.extract(msk, S, param)
		
		tree_cover = iter([])
		
		# tree_indices = list(self.range_to_partial_tree(min_val, max_val))
		# tree_S = [n['index'] for n in tree_indices]
		# tree_K_s = self.kac_layer.extract(msk, tree_S, param)
		# ct = [self.ct[i] for i in tree_S]
		# plain = iter(self.kac_layer.decrypt_set(tree_K_s, tree_S, tree_S, ct, param))



		# for n in tree_indices:
		# 	i = n['index']
		# 	p = plain.next()
		# 	# print p
		# 	root = HashTree(p, self.KAC_to_range(i)['min'], self.KAC_to_range(i)['max'])
		# 	tree_cover = itertools.chain(tree_cover, root.generate_range(n['min'], n['max']))

		for n in self.range_to_partial_tree(min_val, max_val):
			# print 'tree_cover', 
			
			# print self.root_nodes[n['index']].generate_range(n['min'], n['max'])
			tree_cover = itertools.chain(tree_cover, self.root_nodes[n['index']].generate_range(n['min'], n['max']))
			# print 'real', n['index'], self.root_nodes[n['index']].min_val, self.root_nodes[n['index']].max_val, n['min'], n['max'], self.root_nodes[n['index']].data

		return (K_s, S, tree_cover)

	# def aggregate_precompute(self, msk, param_exp, min_val, max_val):
	# 	KAC_index_range = self.range_to_KAC(min_val, max_val)
	# 	# start <= i < end
	# 	K_s = None 
	# 	S = None
	# 	if (KAC_index_range is not None):
	# 		S = [i for i in xrange(KAC_index_range['min'],KAC_index_range['max']+1)]
	# 		K_s = self.kac_layer.extract_precompute(msk, S, param_exp)
	
	# 	tree_cover = iter([])
	# 	for n in self.range_to_partial_tree(min_val, max_val):
	# 		# print 'tree_cover', n['index'] 
	# 		tree_cover = itertools.chain(tree_cover, self.root_nodes[n['index']].generate_range(n['min'], n['max']))

	# 	return (K_s, S, tree_cover)

	def derive_keys(self, aggregate_key, param, min_val, max_val):
		plain = [None] * (max_val)
		K_s, S, tree_cover = aggregate_key
		
		if (K_s is not None):
			KAC_index_range = self.range_to_KAC(min_val, max_val)
			if (KAC_index_range is not None):
				
				kac_start = KAC_index_range['min']
				kac_end = KAC_index_range['max']+1


				# # kac_start <= i < kac_end+1
				# root = self.kac_layer.decrypt_range(K_s, S, kac_start, kac_end, self.ct[kac_start:kac_end], param)
				root = []
				for i in S:
					root.append(self.kac_layer.decrypt(K_s, S, i, self.ct[i], param))

				n = iter(root)
				tree_cover = itertools.chain(tree_cover, (HashTree(n.next(), self.KAC_to_range(i)['min'], self.KAC_to_range(i)['max']) for i in range(kac_start, kac_end)) )
		
		leaves = iter([])
		if (tree_cover is not None):
			for cover in tree_cover:
				leaves = itertools.chain(leaves, cover.generate_tree())
				# for leaf in nodes:
				# 	plain[leaf.min_val] = leaf.data
		
		return leaves

		# if (tree_cover2 is not None):
		# 	for cover in tree_cover2:
		# 		nodes = cover.generate_tree()
		# 		for leaf in nodes:
		# 			plain[leaf.min_val] = leaf.data
		# return plain

		
	def generate_keys(self):
		frame_keys = iter([None])
		for n in self.root_nodes:	
			if (n is not None):
				frame_keys = itertools.chain(frame_keys, n.generate_tree())
		return frame_keys

	def KAC_to_range(self, i):
		min_val = (i-1)*self.leaf_count + 1
		max_val = min_val + self.leaf_count

		return {'min': min_val, 'max': max_val}

	def range_to_KAC(self, min_val, max_val):
		min_index = int(math.ceil((min_val-1.0)/self.leaf_count)+1)
		max_index = (max_val-1)/self.leaf_count
		if (min_index > max_index):
			return None
		return {'min': min_index, 'max': max_index}

	def range_to_partial_tree(self, min_val, max_val):
		#kac_range = range_to_KAC(min_val, max_val)
		min_boundary = (min_val-1)%self.leaf_count
		max_boundary = (max_val-1)%self.leaf_count

		# if not start is not at boundary, we need to find minimum cover
		first_subrange = None
		last_subrange = None
		last_index = -2
		first_index = -1
		if (min_boundary!=0):
			first_index = (min_val-1)/self.leaf_count + 1
			first_subrange = {'index':first_index, 'min': min_val, 'max': self.KAC_to_range(first_index)['max']}
			

		if (max_boundary!=0):
			last_index = (max_val-1)/self.leaf_count + 1
			if (first_index!=last_index):
				yield {'index': last_index, 'min': self.KAC_to_range(last_index)['min'], 'max': max_val}
			else:
				yield {'index': last_index, 'min': min_val, 'max': max_val}
				return

		if (min_boundary!=-0):
			yield first_subrange

def main():
	# start_frame <= i < end_frame
	
	n = 2 ** 16
	q = n/2
	exponents = [i for i in xrange(1,2)]
	list_m = [(2**i) for i in exponents]
	encrypt_time = []
	extract_time = []
	decrypt_time = []
	public_space = []
	private_space = []
	aggregate_size = []
	iterations = 512
	for m in list_m:
		ag_size = 0.0
		
		test = KAC_Tree(n, m)



		storage = {}

		start = time.clock()
		storage['kac_size'] = test.kac_size
		storage['leaf_count'] = test.leaf_count
		storage['param'] = test.setup()
		storage['e_g1_g2'] = test.kac_layer.e_g1_g2

		# print param
		storage['key'] = test.keygen(storage['param'])

		# encrypting
		storage['cipher'] = test.encrypt(storage['key']['pk'], storage['param'])
		end = time.clock()
		encrypt_time.append((m, end-start))

		start = time.clock()
		start_frame, end_frame = generate_start_end(n, q)
		end = time.clock()
		range_gen_time = end-start
		
		start = time.clock()
		for i in xrange(iterations):
			start_frame, end_frame = generate_start_end(n, q)
			# aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
			aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
			ag_size += aggregate_key_size(aggregate_key)
		end = time.clock()
		extract_time.append((m, (end-start)/iterations - range_gen_time))
		aggregate_size.append((m, ag_size/iterations))
		

		aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
		start = time.clock()
		y = list(test.derive_keys(aggregate_key, storage['param'], start_frame, end_frame))
		end = time.clock()
		

		if (verify_results(y, start_frame, end_frame, test) == False):
			decrypt_time.append((m, 'error'))
		else:
			decrypt_time.append((m, end-start))
		

		public, private = getStorageSize(storage)
		public_space.append((m, public))
		private_space.append((m, private))

	print decrypt_time


	# with open('kac_layer_public_space.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['m','bytes'])
	#     for row in public_space:
	#         csv_out.writerow(row)

	# with open('kac_layer_private_space.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['m','bytes'])
	#     for row in private_space:
	#         csv_out.writerow(row)

	# with open('kac_layer_aggregate_size.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['m','bytes'])
	#     for row in aggregate_size:
	#         csv_out.writerow(row)

	# with open('kac_layer_encrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['m','time(s)'])
	#     for row in encrypt_time:
	#         csv_out.writerow(row)


	# with open('kac_layer_extract_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['m','time(s)'])
	#     for row in extract_time:
	#         csv_out.writerow(row)

	with open('kac_layer_decrypt_time.csv','w') as out:
	    csv_out=csv.writer(out)
	    csv_out.writerow(['m','time(s)'])
	    for row in decrypt_time:
	        csv_out.writerow(row)




	# list_q = [(2**i) for i in xrange(1,16)]
	# n = 2 ** 16
	# test = KAC_Tree(n, 2**6)
	# iterations = 256

	# encrypt_time = []
	# extract_time = []
	# decrypt_time = []
	# public_space = []
	# private_space = []
	# aggregate_size = []

	# storage = {}
	# storage['kac_size'] = test.kac_size
	# storage['leaf_count'] = test.leaf_count
	# storage['param'] = test.setup()
	# storage['e_g1_g2'] = test.kac_layer.e_g1_g2

	# # print param
	# storage['key'] = test.keygen(storage['param'])

	# # encrypting
	# storage['cipher'] = test.encrypt(storage['key']['pk'], storage['param'])

		
	# for q in list_q:
	# 	ag_size = 0.0
	# 	start = time.clock()
	# 	start_frame, end_frame = 1,1
	# 	end = time.clock()
	# 	range_gen_time = end-start
	# 	y = None
		
	# 	start = time.clock()
	# 	for i in xrange(iterations):
	# 		start_frame, end_frame = generate_start_end(n, q)
	# 		# aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
	# 		aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
	# 		ag_size += aggregate_key_size(aggregate_key)
	# 	end = time.clock()
	# 	keygen = end-start
	# 	extract_time.append((q, (keygen)/iterations - range_gen_time))
	# 	aggregate_size.append((q, ag_size/iterations))

	# 	if (q<=128):
	# 		start = time.clock()
	# 		for i in xrange(iterations):
	# 			start_frame, end_frame = generate_start_end(n, q)
	# 			aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
	# 			y = list(test.derive_keys(aggregate_key, storage['param'], start_frame, end_frame))
	# 		end = time.clock()
	# 		d_time = ((end-start)-keygen)/iterations

	# 	else:

	# 		start_frame, end_frame = generate_start_end(n, q)
	# 		aggregate_key = test.aggregate(storage['key']['msk'], storage['param'], start_frame,end_frame)
	# 		start = time.clock()
	# 		y = list(test.derive_keys(aggregate_key, storage['param'], start_frame, end_frame))
	# 		end = time.clock()
	# 		d_time = end-start

	# 	if (verify_results(y, start_frame, end_frame, test) == False):
	# 		decrypt_time.append((q, 'error'))
	# 	else:
	# 		decrypt_time.append((q, d_time))

	# print decrypt_time

	# # with open('kac_layer_aggregate_size_m64.csv','w') as out:
	# #     csv_out=csv.writer(out)
	# #     csv_out.writerow(['q','bytes'])
	# #     for row in aggregate_size:
	# #         csv_out.writerow(row)



	# # with open('kac_layer_extract_time_size_m64.csv','w') as out:
	# #     csv_out=csv.writer(out)
	# #     csv_out.writerow(['q','time(s)'])
	# #     for row in extract_time:
	# #         csv_out.writerow(row)

	# with open('kac_layer_decrypt_time_m64.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['q','time(s)'])
	#     for row in decrypt_time:
	#         csv_out.writerow(row)




def generate_start_end(n, q):
	start = random.randint(1, n-q)
	return start, start+q



def aggregate_key_size(aggregate_key):
		ag = {} 
		if (aggregate_key[0] is not None):
			ag['K_s'] = objectToBytes(aggregate_key[0], group)
			ag['S'] = {}
			ag['S']['start_frame'] = min(aggregate_key[1])
			ag['S']['end_frame'] = max(aggregate_key[1])
		ag['tree_cover'] = list(aggregate_key[2])
		# print getsizeof(pickle.dumps(ag['tree_cover']))
		return getsizeof(pickle.dumps(ag))

def getStorageSize(storage):
	
	public = {}
	public['pk'] = objectToBytes(storage['key']['pk'], group)
	public['param'] = objectToBytes(storage['param'], group)
	public['cipher'] = objectToBytes(storage['cipher'], group)
	public['kac_size'] = storage['kac_size']
	public['leaf_count'] = storage['leaf_count']

	private = {}
	private['kac_size'] = storage['kac_size']
	private['leaf_count'] = storage['leaf_count']
	private['msk'] = objectToBytes(storage['key']['msk'], group)
	private['param'] = objectToBytes(storage['param'], group)
	private['e_g1_g2'] = objectToBytes(storage['e_g1_g2'],group) 

	return getsizeof(pickle.dumps(public)), getsizeof(pickle.dumps(private))

def verify_results(calculated, start, end, kac):
	x = sorted(calculated, key=lambda HashTree: HashTree.min_val)
	plain = itertools.islice(kac.generate_keys(), start, end)
	i = 1
	check = True
	for frame_key in x:
		y = plain.next().data
		if (frame_key.data!=y):
			print start, i
			print frame_key.data, y
			return False
		i+=1
	return check


if __name__ == "__main__":
	main()