
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject

import time, json, pickle, os
#n=5

class KAC:

	def __init__(self, groupObj='SS512'):
		self.n = None
		self.param = None
		self.e_g1_g2 = None
		global group
		group = PairingGroup('SS512')

	def setup(self, n):
		self.n = n
		a = group.random(ZR)
		param = [group.random(G1)]
		for i in range(1, 2 * self.n):
			param.append(param[0] ** (a ** i))
		self.param = param
		self.e_g1_g2 = pair(param[1], param[n])
		return param

	def keygen(self):
		y = group.random(ZR)
		pk = self.param[0] ** y
		return {'pk': pk, 'msk': y}

	# pk = v
	def encrypt(self, pk, i, m, param):
		t = group.random(ZR)
		return (self.param[0] ** t, (pk * self.param[i]) ** t, m * (self.e_g1_g2 ** t) )

	#msk = y
	def extract(self, msk, S, param):
		K_s = group.init(G1, 1)
		for i in S:
			K_s *= (self.param[self.n+1-i] ** msk)
		return K_s

	def decrypt(self, K_s, S, i, ct):
		aggregate1 = group.init(G1, 1)
		aggregate2 = group.init(G1, 1)
		result = None

		if i in S:
			for j in S:
				if j!=i:
					aggregate1 *= self.param[self.n+1-j+i]
				aggregate2 *= self.param[self.n+1-j]
			result =  ct[2] * pair(K_s * aggregate1, ct[0]) / pair(aggregate2, ct[1]) 


		# granDict = group.GetGranularBenchmarks()
		# print("<=== Granular Benchmarks ===>")
		# print("G mul   := ", granDict["Mul"][G1])
		# print("G exp   := ", granDict["Div"][G1])
	def decrypt_set(self, K_s, S, S_2, ct):

		count=0
		aggregate2 = group.init(G1, 1)
		result = []
		for j in S:
			aggregate2 *= self.param[self.n+1-j]
		for i in S_2:
			aggregate1 = group.init(G1, 1)
			for j in S:
				if j!=i:
					aggregate1 *= self.param[self.n+1-j+i]
			result.append(ct[count][2] * pair(K_s * aggregate1, ct[count][0]) / pair(aggregate2, ct[count][1]) )
			count+=1

		return result


	def decrypt_range(self, K_s, S, start, end, ct):

		
		aggregate2 = group.init(G1, 1)
		aggregate1 = group.init(G1, 1)
		result = []

		for j in S:
			aggregate2 *= self.param[self.n+1-j]
			if j!=start: aggregate1 *= self.param[self.n+1-j+start]
			#else: hole = self.n+1-j+start
		result.append(ct[0][2] * pair(K_s * aggregate1, ct[0][0]) / pair(aggregate2, ct[0][1]) )

		count = end-start-1

		sorted_sublist = self.extract_consecutive_sublists(S)

		for i in range(count):
			for k in sorted_sublist:
				#print(k)
				#if ((start+i+1) != j): aggregate1 *= self.param[self.n+1-j+start+i+1]
				#else: hole = self.n+1-j+start+i+1
				if ((start+i+1) != k[0]): aggregate1 *= self.param[self.n+1-k[0]+start+i+1]
				#aggregate1 /= self.param[self.n+1-S[0]+start+i]
				aggregate1 /= self.param[self.n+1-k[1]+start+i]
			result.append(ct[i+1][2] * pair(K_s * aggregate1, ct[i+1][0]) / pair(aggregate2, ct[i+1][1]) )


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


test = KAC()
param = None
if not os.path.isfile('param.txt'):
	param = test.setup(8000)
	pickle.dump(objectToBytes(param, group), open( "param.txt", "wb" ) )
	pickle.dump(test.n, open( "n.txt", "wb" ) )
	pickle.dump(objectToBytes(test.e_g1_g2, group), open( "e_g1_g2.txt", "wb" ) )
	#print(objectToBytes(param, group))
else:
	test.param = bytesToObject(pickle.load( open( "param.txt", "rb" ) ), group)
	#print(test.param)
	test.n = pickle.load( open( "n.txt", "rb" ) )
	test.e_g1_g2 = bytesToObject(pickle.load( open( "e_g1_g2.txt", "rb" ) ), group)

key = None
if not os.path.isfile('key.txt'):
	key = test.keygen()
	pickle.dump(objectToBytes(key, group), open( "key.txt", "wb" ) )
else:
	key = bytesToObject(pickle.load( open( "key.txt", "rb" ) ), group)

K_s = None
S = [i+1 for i in range(6000)]
# S.extend([i for i in range(7000,8000)])
# S.extend([i for i in range(20000,40000)])
if not os.path.isfile('K_s.txt'):
	K_s = test.extract(key['msk'], S, param)
	pickle.dump(objectToBytes(K_s, group), open( "K_s.txt", "wb" ) )
else:
	K_s = bytesToObject(pickle.load( open( "K_s.txt", "rb" ) ), group)


m=[]
ciphertext = []
if not os.path.isfile('ciphertext.txt'):
	for i in range(1,4000): 
		plain = group.random(GT)
		m.append(plain)
		ciphertext.append(test.encrypt(key['pk'], i, plain, param))
	pickle.dump(objectToBytes(m, group), open( "m.txt", "wb" ) )
	pickle.dump(objectToBytes(ciphertext, group), open( "ciphertext.txt", "wb" ) )
else:
	m = bytesToObject(pickle.load( open( "m.txt", "rb" ) ), group)
	ciphertext = bytesToObject(pickle.load( open( "ciphertext.txt", "rb" ) ), group)


# assert group.InitBenchmark(), "failed to initialize benchmark"
# group.StartBenchmark(["Mul", "Div", "Pair", "RealTime"])

# S2 = [i for i in range(1,4000)]
# m2 = test.decrypt_set(K_s, S, S2, ciphertext)

#for i in range(1,2000):
#	ans = test.decrypt(K_s, S, i, ciphertext[i-1])
start = time.clock()
m3 = test.decrypt_range(K_s, S, 1, 4000, ciphertext)
end = time.clock()
# group.EndBenchmark()
print end-start


# print(m2[0])
# print(m[0])

#assert (set(m2) == set(m)), "Same set"

# assert group.InitBenchmark(), "failed to initialize benchmark"
# group.StartBenchmark(["Mul", "Div", "RealTime"])

# for i in range(1,3):
# 	ans = test.decrypt(K_s, S, i, ciphertext[i-1])
# group.EndBenchmark()

# assert (ans == m[0]), "Failure"
#print(m)
#print(m3)

if (m == m3): print("equal")
else: print("not equal")


# msmtDict = group.GetGeneralBenchmarks()
# print("<=== General Benchmarks ===>")
# print("Mul := ", msmtDict["Mul"])
# print("Div := ", msmtDict["Div"])
# print("Pair := ", msmtDict["Pair"])
# print("Without: ", group.GetBenchmark("RealTime"))

