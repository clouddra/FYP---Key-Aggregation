
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject
from charm.toolbox.integergroup import IntegerGroup
from charm.toolbox.hash_module import Hash

import time, json, pickle, os, random, csv, copy
from sys import getsizeof
#n=5

class KAC:

	def __init__(self, groupObj='SS512'):
		self.n = None
		self.e_g1_g2 = None
		global group
		group = PairingGroup(groupObj)
		self.group = group

	def setup(self, n):
		self.n = n
		a = group.random(ZR)
		param = [group.random(G1)]
		for i in range(1, (2 * self.n)+1):
			param.append(param[0] ** (a ** i))
		self.e_g1_g2 = pair(param[1], param[n])
		

		return param

	def keygen(self, param):
		y = group.random(ZR)
		pk = param[0] ** y
		return {'pk': pk, 'msk': y}

	# pk = v
	def encrypt(self, pk, i, m, param):
		t = group.random(ZR)
		return (param[0] ** t, (pk * param[i]) ** t, m * (self.e_g1_g2 ** t) )

	#msk = y
	def extract(self, msk, S, param):
		K_s = group.init(G1, 1)
		for i in S:
			K_s *= param[self.n+1-i]
		K_s = K_s ** msk
		return K_s

		#msk = y

	def decrypt(self, K_s, S, i, ct, param):
		aggregate1 = group.init(G1, 1)
		aggregate2 = group.init(G1, 1)
		result = None

		if i in S:
			for j in S:
				if j!=i:
					aggregate1 *= param[self.n+1-j+i]
				aggregate2 *= param[self.n+1-j]
			result =  ct[2] * pair(K_s * aggregate1, ct[0]) / pair(aggregate2, ct[1]) 

		return result


		# granDict = group.GetGranularBenchmarks()
		# print("<=== Granular Benchmarks ===>")
		# print("G mul   := ", granDict["Mul"][G1])
		# print("G exp   := ", granDict["Div"][G1])
	def decrypt_set(self, K_s, S, S_2, ct, param):

		count=0
		aggregate2 = group.init(G1, 1)
		result = []
		for j in S:
			aggregate2 *= param[self.n+1-j]
		for i in S_2:
			aggregate1 = group.init(G1, 1)
			for j in S:
				if j!=i:
					aggregate1 *= param[self.n+1-j+i]
			result.append(ct[count][2] * pair(K_s * aggregate1, ct[count][0]) / pair(aggregate2, ct[count][1]) )
			count+=1

		return result


	def decrypt_range(self, K_s, S, start, end, ct, param):

		aggregate2 = group.init(G1, 1)
		aggregate1 = group.init(G1, 1)
		result = []

		for j in S:
			aggregate2 *= param[self.n+1-j]
			if j!=start: aggregate1 *= param[self.n+1-j+start]
			#else: hole = self.n+1-j+start
		result.append(ct[0][2] * pair(K_s * aggregate1, ct[0][0]) / pair(aggregate2, ct[0][1]) )

		count = end-start-1

		sorted_sublist = self.extract_consecutive_sublists(S)

		for i in range(count):
			for k in sorted_sublist:
				#print(k)
				#if ((start+i+1) != j): aggregate1 *= self.param[self.n+1-j+start+i+1]
				#else: hole = self.n+1-j+start+i+1
				if ((start+i+1) != k[0]): aggregate1 *= param[self.n+1-k[0]+start+i+1]
				#aggregate1 /= self.param[self.n+1-S[0]+start+i]
				aggregate1 /= param[self.n+1-k[1]+start+i]
			result.append(ct[i+1][2] * pair(K_s * aggregate1, ct[i+1][0]) / pair(aggregate2, ct[i+1][1]) )
		return result




		# for i in S_2:
		# 	aggregate1 = group.init(G1, 1)
		# 	count=0
		# 	for j in S:
		# 		if j!=i:
		# 			aggregate1 *= self.param[self.n+1-j+i]
		# 	result.append(ct[count][2] * pair(K_s * aggregate1, ct[count][0]) / pair(aggregate2, ct[count][1]) )
		# 	count+=1

		return result


	def extract_consecutive_sublists(self, S):
		start=end=S[0]
		sorted_sublist = []

		for j in range(len(S)):
			if (j+1<len(S) and (S[j]+1) == S[j+1]):
				end+=1
			else:
				end = S[j]
				sorted_sublist.append((start, end))
				if (j+1<len(S)): start = S[j+1]

		return(sorted_sublist)

	def param_sig_gen(self, param, msk):
		r = group.hash((msk, 'alpha'), ZR)
		g_r = group.hash(msk, G1)
		i=0
		param_sig = []
		for p in param:
			r_i = group.hash((r, i), ZR)
			param_sig.append((p ** r) * (g_r ** r_i))
		return param_sig
	
	def aggregate_param_sig(self, msk, S, param, param_sig):
		K_s_pub = group.init(G1, 1)
		K_s_sig = group.init(G1, 1)
		for i in S:
			K_s_pub *= param[self.n+1-i]
			K_s_sig *= param_sig[self.n+1-i]
		return K_s_pub, K_s_sig		

	def extract_param_sig(self, msk, S, K_s_pub, K_s_sig):
		r = group.hash((msk, 'alpha'), ZR)
		g_r = group.hash(msk, G1)
		exponent_sum = group.init(ZR, 0)
		for i in S:
			j = self.n+1-i
			exponent_sum += group.hash((r, j), ZR)
		computed_sig = (K_s_pub ** r) * (g_r ** exponent_sum)
		print computed_sig
		print K_s_sig
		if computed_sig == K_s_sig:
			return K_s_pub ** msk
		else:
			print "wrong param signature"
		return


def main():

	NORMAL_DECRYPT = 1
	SET_DECRYPT = 2
	RANGE_DECRYPT = 3
	n = 2**16
	list_n = [2**i for i in xrange(16)]
	kac = KAC()
	
	# param = kac.setup(128)
	# key = kac.keygen(param)
	# param_sig = kac.param_sig_gen(param,key['msk'])
	# S = [i+3 for i in xrange(20)]
	# K_s_pub, K_s_sig = kac.aggregate_param_sig(key['msk'], S, param, param_sig)
	# print kac.extract_param_sig(key['msk'], S, K_s_pub, K_s_sig)
	# print kac.extract(key['msk'], S, param)

	rand_collude = group.random(G1)
	rand_collude2 = group.random(G1)
	print group

	group2 = PairingGroup('MNT224')
	print group2
	# print rand_collude2 
	# print rand_collude

	# prime = group1.randomGen()
	# print prime
	# print param[1] ** prime
	alpha = group.random(ZR)
	r_1 =  group.random(ZR)

	print alpha
	check = (rand_collude ** r_1) * (rand_collude ** alpha)
	check2 = rand_collude ** (r_1 + alpha)
	print check
	print check2
	# print mac

	# check2 = mac/(param[1] ** alpha) 


	# ex1 = (param[1] ** alpha) * (param[2]**alpha)
	# ex2 = (param[1] * param[2]) ** alpha
	# # print ex1
	# # print ex2
	# # # h = Hash(group)
	# # # print h.hashToZr(('lol', '1'))
	# # print 'jed', group.hash(str(r_1), ZR)
	# start = time.clock()
	# for i in xrange(10000):
	# 	print 'jed2', group.hash((r_1, r_1), G1)
	# end = time.clock()

	# print end-start
	# print group.hash(r_1, G1)
	# print group.init(ZR, 0)
	# print group.random(GT)
	# print group.random(G1)
	# print group.random(G2)


if __name__ == "__main__":
	main()

