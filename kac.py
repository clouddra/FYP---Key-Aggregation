
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes,bytesToObject

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
		# print here
		a = group.random(ZR)
		param = [group.random(G1)]
		assert param[0].initPP(), "failed to init pre-computation table"
		for i in xrange(1, (2 * self.n)+1):
			param.append(param[0] ** (a ** i))

		self.e_g1_g2 = pair(param[1], param[n])
		assert self.e_g1_g2.initPP(), "failed to init pre-computation table"
		# param[0].initPP()
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


	def decrypt_set(self, K_s, S, Q, ct, param):

		count=0
		aggregate2 = group.init(G1, 1)
		result = []
		for j in S:
			aggregate2 *= param[self.n+1-j]
		for i in Q:
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

		for i in xrange(count):
			for k in sorted_sublist:
				#print(k)
				#if ((start+i+1) != j): aggregate1 *= self.param[self.n+1-j+start+i+1]
				#else: hole = self.n+1-j+start+i+1
				if ((start+i+1) != k[0]): aggregate1 *= param[self.n+1-k[0]+start+i+1]
				#aggregate1 /= self.param[self.n+1-S[0]+start+i]
				aggregate1 /= param[self.n+1-k[1]+start+i]
			result.append(ct[i+1][2] * pair(K_s * aggregate1, ct[i+1][0]) / pair(aggregate2, ct[i+1][1]) )
		return result



	def decrypt_general(self, K_s, S, Q, ct, param):

		aggregate2 = group.init(G1, 1)
		aggregate1 = group.init(G1, 1)
		result = []
		S = sorted(S)
		Q = sorted(Q)
		# print S
		sorted_sublist = self.extract_consecutive_sublists(S)
		improvement = 0

		for j in S:
			aggregate2 *= param[self.n+1-j]
			if j!=Q[0]: aggregate1 *= param[self.n+1-j+Q[0]]
			#else: hole = self.n+1-j+start
		result.append(ct[0][2] * pair(K_s * aggregate1, ct[0][0]) / pair(aggregate2, ct[0][1]) )

		for i in xrange(1, len(Q)):
			d = Q[i] - Q[i-1]
			improvement = len(S) - (2 * len(sorted_sublist) * d)
			if (improvement>0):
				print "improve", improvement
				# print "optimized ver"
				for l in xrange(d):
					for k in sorted_sublist:
						if ((Q[i-1]+l+1) != k[0]): aggregate1 *= param[self.n+1-k[0]+Q[i-1]+l+1]
						aggregate1 /= param[self.n+1-k[1]+Q[i-1]+l]
			else:
				aggregate1 = group.init(G1, 1)
				for j in S:
					if j!=Q[i]:
						aggregate1 *= param[self.n+1-j+Q[i]]
			result.append(ct[i][2] * pair(K_s * aggregate1, ct[i][0]) / pair(aggregate2, ct[i][1]) ) 
		return result




	def extract_consecutive_sublists(self, S):
		S = sorted(S)
		start=end=S[0]
		sorted_sublist = []

		for j in xrange(len(S)):
			if (j+1<len(S) and (S[j]+1) == S[j+1]):
				end+=1
			else:
				end = S[j]
				sorted_sublist.append((start, end))
				if (j+1<len(S)): start = S[j+1]

		return(sorted_sublist)

	def param_sig_gen(self, param, msk):
		assert param[0].initPP(), "failed to init pre-computation table"
		r = group.random(ZR)
		i=0
		param_sig = [param[0]]
		for i in xrange(1,self.n+1):
			r_i = group.hash((r, i), ZR)
			param_sig.append((param[i] ** r) * (param[0] ** r_i))
		return param_sig, r
	
	def aggregate_param_sig(self, msk, S, param, param_sig):
		K_s_pub = group.init(G1, 1)
		K_s_sig = group.init(G1, 1)
		for i in S:
			K_s_pub *= param[self.n+1-i]
			K_s_sig *= param_sig[self.n+1-i]
		return K_s_pub, K_s_sig		

	def extract_param_sig(self, msk, S, K_s_pub, K_s_sig, r, g):
		exponent_sum = group.init(ZR, 0)
		for i in S:
			exponent_sum += group.hash((r, self.n+1-i), ZR)
		computed_sig = (K_s_pub ** r) * (g ** exponent_sum)
		# print computed_sig
		# print K_s_sig
		if computed_sig == K_s_sig:
			return K_s_pub ** msk

		print "wrong param signature"
		return

def main():

	NORMAL_DECRYPT = 1
	SET_DECRYPT = 2
	RANGE_DECRYPT = 3
	GEN_DECRYPT = 4
	n = 2**5
	list_n = [2**i for i in xrange(5)]


	# serialize keys and data for decryption
	if not os.path.isfile('kac.txt'):
		storage = generate_ciphertext_param(n)
		ss = serialize(storage)
		with open('kac.txt', 'w') as outfile:
	  		json.dump(serialize(storage), outfile)

	else:
		with open('kac.txt', 'r') as infile:
  			storage = deserialize(json.load(infile))


  	
	
	

	# encrypt_timings, public_space, private_space = encrypt_time_space(list_n)
	# with open('kac_encrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in encrypt_timings:
	#         csv_out.writerow(row)

	# with open('kac_public_space.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in public_space:
	#         csv_out.writerow(row)

	# with open('kac_private_space.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in private_space:
	#         csv_out.writerow(row)


	extract_time, aggregate_size = extraction_time(storage, list_n)

	with open('kac_extract_time_fast.csv','w') as out:
	    csv_out=csv.writer(out)
	    csv_out.writerow(['n','time(s)'])
	    for row in extract_time:
	        csv_out.writerow(row)

	# au_time, verification_time = mac_scheme(storage, list_n)
	# print au_time, verification_time
  	 

	# with open('kac_mac_au_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['S','time(s)'])
	#     for row in au_time:
	#         csv_out.writerow(row)

	# with open('kac_mac_verify_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['S','time(s)'])
	#     for row in verification_time:
	#         csv_out.writerow(row)

	# extract_time, aggregate_size, decrypt_time = decryption_time(storage, list_n, RANGE_DECRYPT)

	# with open('kac_extract_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in extract_time:
	#         csv_out.writerow(row)

	# with open('kac_aggregate_size.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in aggregate_size:
	#         csv_out.writerow(row)

	# with open('kac_range_decrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in decrypt_time:
	#         csv_out.writerow(row)



 #  	extract_time, aggregate_size, decrypt_time = decryption_time(storage, list_n, SET_DECRYPT)
	# with open('kac_set_decrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in decrypt_time:
	#         csv_out.writerow(row)

 # 	decrypt_time = decryption_time(storage, list_n, NORMAL_DECRYPT)
	# with open('kac_normal_decrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in decrypt_time:
	#         csv_out.writerow(row)

	# aggregate_time, aggregate_size, decrypt_time = decryption_time(storage, list_n)
	# print aggregate_size, aggregate_time
	# extract_time, aggregate_size = extraction_time(storage, list_n)
	# print aggregate_size, extract_time

	extract_time, aggregate_size, decrypt_time, improvements = decryption_time(storage, list_n, GEN_DECRYPT)

	print decrypt_time, improvements

	with open('kac_gen_decrypt_time.csv','w') as out:
	    csv_out=csv.writer(out)
	    csv_out.writerow(['n','time(s)'])
	    for row in decrypt_time:
	        csv_out.writerow(row)


def mac_scheme(storage, q_list):
	param_sig_time = []
	au_time = []
	verification_time = []
	kac = KAC()
	kac.n = storage['n']
	
	param_sig, r = kac.param_sig_gen(storage['param'], storage['key']['msk'])
	iterations = 256
	for q in q_list:
		
		S = generateS(storage, q)

		start = time.clock()
		for i in xrange(iterations):
			K_s_pub, K_s_sig = kac.aggregate_param_sig(storage['key']['msk'], S, storage['param'], param_sig)
		end = time.clock()
		au_time.append((q, (end-start)/iterations))

		K_s_pub, K_s_sig = kac.aggregate_param_sig(storage['key']['msk'], S, storage['param'], param_sig)

		start = time.clock()
		for i in xrange(iterations):
			K_s = kac.extract_param_sig(storage['key']['msk'], S, K_s_pub, K_s_sig, r, storage['param'][0])
		end = time.clock()

		K_s = kac.extract_param_sig(storage['key']['msk'], S, K_s_pub, K_s_sig, r, storage['param'][0])

		if (K_s== kac.extract(storage['key']['msk'], S, storage['param'])):
			verification_time.append((q, (end-start)/iterations))
		else:
			verification_time.append((q, 'error'))

	return au_time, verification_time

def decryption_time(storage, q_list, decrypt_type=3):
	iterations = 1
	kac = KAC()
	kac.n = storage['n']
	kac.e_g1_g2 = storage['e_g1_g2']
	timings = []
	extract_time = []
	aggregate_size = []

	
	for q in q_list:
		check = True
		timing = 0.0
		gen_timing = 0.0
		for i in xrange(iterations):
			S = generateS(storage, q)	 

			# S = sorted(random.sample(xrange(1, storage['n']), q))
			Q = S
			start = time.clock()
			K_s = kac.extract(storage['key']['msk'], S, storage['param'])

			end = time.clock()
			gen_timing += end-start 

			# start_frame = S[0]
			# end_frame = S[len(S)-1]+1
			# ct = storage['cipher'][start_frame:end_frame]
			# plain = storage['plain'][start_frame:end_frame]
			plain = []
			ct = []
			for i in Q:
				ct.append(storage['cipher'][i])
				plain.append(storage['plain'][i])

			start = time.clock()
			if (decrypt_type==1):
				result = [kac.decrypt(K_s, S, j, storage['cipher'][j], storage['param']) for j in S]
			elif (decrypt_type==2):
				result = kac.decrypt_set(K_s, S, Q, ct, storage['param'])
			elif (decrypt_type==3):
				result = kac.decrypt_range(K_s, S, start_frame, end_frame, ct, storage['param'])
			elif (decrypt_type==4):
				result = kac.decrypt_general(K_s, S, Q, ct, storage['param'])
			end = time.clock()
			timing += end-start
			if (result!=plain):
				check = false

		extract_time.append((q, gen_timing/iterations))
		aggregate_size.append((q, getsizeof(pickle.dumps(objectToBytes(K_s, group)))))
		
		if (check==True):
			timings.append((q, timing/iterations))
		else:
			timings.append((q, 'error'))

	# print timings
	# return extrchainact_time, aggregate_size, timings
	return extract_time, aggregate_size, timings



def extraction_time(storage, q_list):
	iterations = 50
	kac = KAC()
	kac.n = storage['n']
	kac.e_g1_g2 = storage['e_g1_g2']
	timings = []
	aggregate_size = []

	for q in q_list:
		timing = 0.0
		for i in xrange(iterations):
			S = generateS(storage, q)	 
			start = time.clock()
			K_s = kac.extract(storage['key']['msk'], S, storage['param'])
			end = time.clock()
			timing+=end-start
		timings.append((q, timing/iterations))
		aggregate_size.append((q, getsizeof(pickle.dumps(objectToBytes(K_s,group))) ))
	# print timings
	return timings, aggregate_size

def encrypt_time_space(list_n):
	iterations = 1
	private = public = 0
	timings = []
	private_space = []
	public_space = []
	for n in list_n:
		start = time.clock()
		for i in xrange(iterations):	
			storage = generate_ciphertext_param(n)
		end = time.clock()
		public, private = getStorageSize(storage)
		timings.append((n, (end-start)/iterations))
		private_space.append((n, private))
		public_space.append((n, public))
		# space.append((n, private/iterations, public/iterations))
		
	# print timings
	return timings, public_space, private_space

def generate_ciphertext_param(n):
	kac = KAC()
	storage = {}

	storage['n'] = n

	# sentinel values
	storage['plain'] = [group.random(GT)]
	storage['cipher'] = [group.random(GT)]

	storage['param'] = kac.setup(n)
	storage['e_g1_g2'] = kac.e_g1_g2
	storage['key'] = kac.keygen(storage['param'])

	for i in range(1,n+1): 
		plain = group.random(GT)
		storage['plain'].append(plain)
		storage['cipher'].append(kac.encrypt(storage['key']['pk'], i, plain, storage['param']))
	
	return storage

def serialize(s):
	storage = {}
	storage['n'] = s['n']
	storage['param'] = objectToBytes(s['param'], group)
	storage['e_g1_g2'] = objectToBytes(s['e_g1_g2'], group)
	storage['key'] = objectToBytes(s['key'], group)
	storage['plain'] = objectToBytes(s['plain'], group)
	storage['cipher'] = objectToBytes(s['cipher'], group)
	return storage

def deserialize(storage):
	kac = KAC()
	kac.n = storage['n']
	storage['param'] = bytesToObject(storage['param'], group)
	storage['e_g1_g2'] = bytesToObject(storage['e_g1_g2'], group)
	kac.e_g1_g2 = storage['e_g1_g2']
	storage['key'] = bytesToObject(storage['key'], group)
	storage['plain'] = bytesToObject(storage['plain'], group)
	storage['cipher'] = bytesToObject(storage['cipher'], group)

	return storage

def getStorageSize(storage):
	public = {}
	public['pk'] = objectToBytes(storage['key']['pk'], group)
	public['param'] = objectToBytes(storage['param'], group)
	public['cipher'] = objectToBytes(storage['cipher'], group)

	private = {}
	private['n'] = storage['n']
	private['msk'] = objectToBytes(storage['key']['msk'], group)
	private['param'] = objectToBytes(storage['param'], group)
	private['e_g1_g2'] = objectToBytes(storage['e_g1_g2'],group) 
	

	# print getsizeof(pickle.dumps(public))
	# print getsizeof(pickle.dumps(private))
	return getsizeof(pickle.dumps(public)), getsizeof(pickle.dumps(private))

def generateS(storage, q):
		if (q>=storage['n']):
			return [i+1 for i in xrange(storage['n'])]

		start_frame = random.randint(1, storage['n'] - q)
		# kac = KAC()
		# kac.n = storage['n']
		# kac.e_g1_g2 = storage['e_g1_g2']
		return [i+start_frame for i in xrange(q)]
 




if __name__ == "__main__":
	main()

