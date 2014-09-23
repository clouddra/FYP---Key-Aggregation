from kac_tree import KAC_Tree
from binary_tree import Node as HashTree
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
import pickle, itertools

class KAC_Tree_Layer:
	def __init__(self, n, m, l, groupObj='SS512'):
		# 0 is the lowest security level
		self.multi_layers = [KAC_Tree(n, m, groupObj) for i in xrange(l+1)]

	def setup(self):
		return  [i.setup() for i in self.multi_layers]
 
	def keygen(self, param):
		param_iter = iter(param)
		return  [i.keygen(param_iter.next()) for i in self.multi_layers]

	def encrypt(self, pk, param):
		pk_iter = iter(pk)
		param_iter = iter(param)
		# return
		self.ct = [i.encrypt(pk_iter.next(), param_iter.next()) for i in self.multi_layers]
		self.encrypted_leaves = []
		unencrypted_leaves = []
		for kac_layer in self.multi_layers:
			unencrypted_leaves.append(list(kac_layer.generate_keys()))


		# sym_key = pickle.dumps(unencrypted_leaves[3][2])
		# plain = pickle.dumps(unencrypted_leaves[2][2])
		# cipher = SymmetricCryptoAbstraction(sym_key).encrypt(plain)
		# print unencrypted_leaves[2][2].data
		# print pickle.loads(SymmetricCryptoAbstraction(sym_key).decrypt(cipher)).data

		for i in xrange(1,len(unencrypted_leaves)):
			self.encrypted_leaves.append([None])
			for j in xrange(1, len(unencrypted_leaves[i])):
				sym_key = unencrypted_leaves[i][j].data
				plain = pickle.dumps(unencrypted_leaves[i-1][j])
				self.encrypted_leaves[i-1].append(SymmetricCryptoAbstraction(sym_key).encrypt(plain))
		
		# decryption_plain = []
		# for i in xrange(len(self.encrypted_leaves)):
		# 	for j in xrange(1, len(self.encrypted_leaves[i])):
		# 		# print i,j
		# 		sym_key = unencrypted_leaves[i+1][j].data
		# 		# print i, j, sym_key
		# 		cipher = self.encrypted_leaves[i][j]
		# 		decryption_plain.append(pickle.loads(SymmetricCryptoAbstraction(sym_key).decrypt(cipher)))
		
		
		return self.encrypted_leaves, unencrypted_leaves
		# for i in decryption_plain:
		# 	print i.min_val

	def aggregate(self, msk, param, min_val, max_val, l):
		# l is top layer 
		return self.multi_layers[l].aggregate(msk[l], param[l], min_val, max_val)

	def derive_keys(self, aggregate_key, param, min_val, max_val, l, encrypted_leaves):
		# inclusive of layer 0
		top_layer = list(self.multi_layers[l].derive_keys(aggregate_key, param, min_val, max_val))
		yield top_layer

		
		for i in reversed(xrange(l)):
			cipher_iter = iter(encrypted_leaves[i])
			next_layer = []
			# skip 0th frame
			cipher_iter.next()
			for plain in top_layer:
				# print 'lol', len(top_layer)
				sym_key = plain.data
				# print i, sym_key
				cipher = cipher_iter.next()
				next_layer.append(pickle.loads(SymmetricCryptoAbstraction(sym_key).decrypt(cipher)))
			top_layer = next_layer
			yield top_layer

def main():
	start_frame = 1
	end_frame = 25
	l = 3
	test = KAC_Tree_Layer(32, 4, 5)
	param = test.setup()
	key = test.keygen(param)
	pk = [k['pk'] for k in key]
	cipher, unencrypted_leaves = test.encrypt(pk, param)
	msk = [k['msk'] for k in key]
	aggregate_key = test.aggregate(msk, param, start_frame, end_frame, l)
	y = test.derive_keys(aggregate_key, param[l], start_frame, end_frame, l, cipher)
	# for i in y:
	# 	for j in i:
	# 		print j.min_val, j.data
	verify_results(y, start_frame, end_frame, l, test, unencrypted_leaves)
	# t = [1, 2, 3]
	# s = t
	# t = []
	# print s
	# print t

def verify_results(calculated, start, end, l, kac, plain):
	
	# inclusive of layer l and layer 0
	j=0
	for i in reversed(xrange(l+1)):
		p = itertools.islice(plain[i], start, end)
		sort_keys = sorted(calculated.next(), key=lambda HashTree: HashTree.min_val)
		for frame_key in sort_keys:
			j+=1
			if (frame_key.data!=p.next().data):	
				print 'false'
			else:
				print 'true'
	print j
if __name__ == "__main__":
	main()
# test.encrypt(pk, param)
# test.encrypt(pk, param)
# for i in pk2:
# 	print i
