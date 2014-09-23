from binary_tree import Node as HashTree
from kac import KAC
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from hashlib import sha256
import os, itertools, time, random, csv


class MonoTree(HashTree):

	def __init__(self, data, n):
		HashTree.__init__(self, data, 1, n+1) 


	def bfs_encrypt(self, pk, param, kac):
		queue = [self]
		index = 1
		while len(queue)>0:
			current = queue.pop(0)
			
			current.kac_index = index
			

			# print current.kac_index, current.data, current.min_val, current.max_val

			index += 1
			# use kac plaintext to encrypt message
			m = group.random(GT)
			current.kac_cipher = kac.encrypt(pk, current.kac_index, m, param)
			current.cipher = SymmetricCryptoAbstraction(extractor(m)).encrypt(current.data)

			if current.left is not None: 
				queue.append(current.left)
			if current.right is not None: 
				queue.append(current.right)

	def decrypt_range(self, start, end, param, kac, msk):
		leaves = iter([])
		kac_ct = []
		ct = []
		plain = []
		kac_p = []
		S = []

		kac_nodes = sorted(self.lookup_range(start, end), key=lambda node: node.kac_index)
		for n in kac_nodes:
			S.append(n.kac_index)
			kac_ct.append(n.kac_cipher)

		K_s = kac.extract(msk, S, param) 
		start_time = time.clock()
		kac_plain = kac.decrypt_general(K_s, S, S, kac_ct, param)
		
		ct = (i.cipher for i in kac_nodes)
		decrypted = (SymmetricCryptoAbstraction(extractor(k)).decrypt(c) for k, c in itertools.izip(kac_plain, ct))


		for n, m in itertools.izip(kac_nodes, decrypted):
			leaves = itertools.chain(leaves, HashTree(m, n.min_val, n.max_val).generate_tree())
		end_time = time.clock()
		return leaves, end_time-start_time



def main():
	n = 2**16
	list_q = [2**i for i in xrange(16)]
	global group
	kac = KAC()
	group = kac.group
	param = kac.setup(2*n)
	key = kac.keygen(param)
	tree = MonoTree(sha256(os.urandom(100)).hexdigest(), n)
	frame_keys = [i for i in tree.generate_tree()]
	tree.bfs_encrypt(key['pk'], param, kac)
	timings = []
	d_timings = []
	iterations = 100
	# print frame_keys[2:5][1].data
	
	for q in list_q:
		timing=0.0
		d_time = 0.0
		for i in xrange(iterations):
			start, end = generate_start_end(n, q)
			# print start, end
			start_time = time.clock()
			results, decrypt_time = list(tree.decrypt_range(start, end, param, kac, key['msk']))
			end_time = time.clock()
			timing += end_time-start_time
			d_time += decrypt_time
		if (verify_results(results, frame_keys, start, end)==True):
			timings.append((q, timing/iterations))
			d_timings.append((q, d_time/iterations))
		else:
			timings.append((q, "error"))
			d_timings.append((q, "error"))
	print timings, d_timings

	with open('mono_decrypt_time.csv','w') as out:
	    csv_out=csv.writer(out)
	    csv_out.writerow(['q','time(s)'])
	    for row in timings:
	        csv_out.writerow(row)
	with open('mono_decrypt_time_fine.csv','w') as out:
	    csv_out=csv.writer(out)
	    csv_out.writerow(['q','time(s)'])
	    for row in d_timings:
	        csv_out.writerow(row)


def verify_results(leaves, frame_keys, start, end):
	# frame_keys.insert(0, 0)
	# y = frame_keys[start-1:end-1]
	# print y[0].data
	if ([x.data for x in sorted(leaves, key=lambda node: node.min_val)] == [x.data for x in frame_keys[start-1:end-1]]):
		return True
	return False

def generate_start_end(n, q):
	start = random.randint(1, n-q)
	return start, start+q



if __name__ == "__main__":
    main()