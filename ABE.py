from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.toolbox.pairinggroup import PairingGroup,GT
# from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
# from charm.core.math.pairing import hashPair as extractor
from charm.core.engine.util import objectToBytes,bytesToObject
import pickle, time, random, os, json, csv
from sys import getsizeof

def policy_less_than(attr_name, num, no_bits=-1):

	exponent = len(str(bin(num))[2:]) - 1
	if (no_bits > 0):
		if (no_bits < exponent+1):
			print("not enough bits allocated...")
			return ""
			# num = int('1'*no_bits, 2)
			# print(num)
		exponent = no_bits-1

	policy_string = ""
	policy_string = generate_less_than_policy(attr_name, num, exponent, exponent)
	# if (no_bits < exponent+1):
	# 	policy_string += " or " + policy_string.replace("0", "1")
	return policy_string

def generate_less_than_policy(attr_name, i, exponent, no_bits):
	if (i<0):
		return ""

	policy_string = ""
	temp = list('X' * (no_bits+1))
	temp[no_bits-exponent] = '0'
	bitstring = ''.join(temp)
	difference =  i - 2**exponent
	if (difference>0):
		i = difference
		policy_string += '(' + attr_name + '-' + bitstring + " or " + str(generate_less_than_policy(attr_name, i, exponent-1, no_bits)) + ')'
		
	elif(difference<0):
		policy_string += '(' + attr_name + '-' + bitstring + " and " + str(generate_less_than_policy(attr_name, i, exponent-1, no_bits)) + ')'

	else:
		policy_string += attr_name + '-' + bitstring
	return policy_string

def num_to_attribute(attr_name, num, no_bits=-1):
	bitstring = list(bin(num)[2:])

	if (no_bits > 0):
		# shrink attribute if too little bits allocated
		if (no_bits < len(bitstring)):
			bitstring = list('1' * no_bits)

		# pad if number of bits > attribute
		elif (no_bits > len(bitstring)):
			bitstring = list(bin(num)[2:].zfill(no_bits))

	attributes = []
	for i in range(len(bitstring)):
		wildcard = list('X' * (len(bitstring)))
		wildcard[i] = bitstring[i]
		attributes.append(attr_name + '-' + ''.join(wildcard))
	return attributes

def policy_more_than_equal(attr_name, num, no_bits=-1):
	exponent = len(str(bin(num))[2:]) - 1
	if (no_bits > 0):
		if (no_bits < exponent+1):
			print("not enough bits allocated...")
			return ""
			# num = int('1'*no_bits, 2)
			# print(num)
		exponent = no_bits-1

	policy_string = ""
	policy_string = generate_more_than_equal_policy(attr_name, num, exponent, exponent)
	# if (no_bits < exponent+1):
	# 	policy_string += " or " + policy_string.replace("0", "1")
	return policy_string

def generate_more_than_equal_policy(attr_name, i, exponent, no_bits):
	if (i<0):
		return ""

	policy_string = ""
	temp = list('X' * (no_bits+1))
	temp[no_bits-exponent] = '1'
	bitstring = ''.join(temp)
	difference =  i - 2**exponent
	if (difference>0):
		i = difference
		policy_string += '(' + attr_name + '-' + bitstring + " and " + str(generate_more_than_equal_policy(attr_name, i, exponent-1, no_bits)) + ')'
		
	elif(difference<0):
		policy_string += '(' + attr_name + '-' + bitstring + " or " + str(generate_more_than_equal_policy(attr_name, i, exponent-1, no_bits)) + ')'

	else:
		policy_string += attr_name + '-' + bitstring
	return policy_string

def main():

	global group
	group = PairingGroup('SS512')
	n = 2**16
	list_n = [2**i for i in xrange(16)]


	if not os.path.isfile('abe.txt'):
		storage = generate_ciphertext_keys(n)
		ss = serialize(storage)
		with open('abe.txt', 'w') as outfile:
	  		json.dump(serialize(storage), outfile)

	else:
		with open('abe.txt', 'r') as infile:
  			storage = deserialize(json.load(infile))


  	# encrypt_timings, extract_time, public_space, private_space, aggregate_size = encrypt_time_space(list_n)
	# print extract_time
	# with open('abe_encrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in encrypt_timings:
	#         csv_out.writerow(row)

	# with open('abe_public_space.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in public_space:
	#         csv_out.writerow(row)

	# with open('abe_private_space.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in private_space:
	#         csv_out.writerow(row)

	# with open('abe_aggregate_size.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in aggregate_size:
	#         csv_out.writerow(row)

	# with open('abe_extract_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in extract_time:
	#         csv_out.writerow(row)


	# decrypt_time = decryption_time(storage, list_n)
	# print decrypt_time
	# with open('abe_decrypt_time.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','time(s)'])
	#     for row in decrypt_time:
	#         csv_out.writerow(row)


	extract_time, aggregate_size =  calculate_aggregate_size(list_n, n)
	print extract_time

	# with open('abe_aggregate_size.csv','w') as out:
	#     csv_out=csv.writer(out)
	#     csv_out.writerow(['n','bytes'])
	#     for row in aggregate_size:
	#         csv_out.writerow(row)

	with open('abe_extract_time.csv','w') as out:
	    csv_out=csv.writer(out)
	    csv_out.writerow(['n','time(s)'])
	    for row in extract_time:
	        csv_out.writerow(row)


def calculate_aggregate_size(list_q, n):
	kpabe = KPabe(group)
	more_than = 1
	iterations = 10
	aggregate_size = []
	aggregate_time = []
	storage = {}
	storage['n'] = n
	no_of_bits = len(list(bin(n)[2:]))+1
	storage['master_public_key'], storage['master_key'] = kpabe.setup()


	for q in list_q:
		gen_timing = 0.0

		for i in xrange(iterations):
			more_than_equal, less_than = generate_range(storage, q)	 
			policy = policy_less_than('A', less_than, no_of_bits) + " and " + policy_more_than_equal('A', more_than_equal, no_of_bits)
			start = time.clock()
			secret_key = kpabe.keygen(storage['master_public_key'], storage['master_key'], policy)
			end = time.clock()
			gen_timing += end-start
		
		aggregate_size.append((q, getsizeof(pickle.dumps(objectToBytes(secret_key, group)))))
		aggregate_time.append((q, (gen_timing)/iterations))
	return aggregate_time, aggregate_size

def encrypt_time_space(list_n):
	iterations = 1

	private = public = 0
	encrypt_timings = []
	aggregate_time = []
	aggregate_size = []
	private_space = []
	public_space = []
	for n in list_n:
		start = time.clock()
		for i in xrange(iterations):	
			storage = generate_ciphertext_keys(n)
		end = time.clock()
		no_of_bits = len(list(bin(n)[2:]))+1
		kpabe = KPabe(group)

		encrypt_timings.append((n, (end-start)/iterations))
		policy = policy_less_than('A', n+1, no_of_bits) + " and " + policy_more_than_equal('A', 1, no_of_bits)
		start = time.clock()
		for i in xrange(iterations):
			secret_key = kpabe.keygen(storage['master_public_key'], storage['master_key'], policy)
		end = time.clock()	
		aggregate_size.append((n, getsizeof(pickle.dumps(objectToBytes(secret_key, group)))))
		aggregate_time.append((end-start)/iterations)
		public, private = getStorageSize(storage)
		private_space.append((n, private))
		public_space.append((n, public))

	return encrypt_timings, aggregate_time, public_space, private_space, aggregate_size

def generate_ciphertext_keys(n):
		storage = {}
		storage['n'] = n

		kpabe = KPabe(group)
		more_than = 1
		storage['plain'] = [group.random(GT)]
 		storage['cipher'] = [group.random(GT)]
		no_of_bits = len(list(bin(n)[2:]))+1
		
		storage['master_public_key'], storage['master_key'] = kpabe.setup()
		frames_attribute = (num_to_attribute('A', i, no_of_bits) for i in xrange(1, n+1))
				
		for i in xrange(n): 
			plain = group.random(GT)
			storage['plain'].append(plain)
			storage['cipher'].append(kpabe.encrypt(storage['master_public_key'], plain, frames_attribute.next()))			
		
		# ct = storage['cipher'][1:n+1]
		# result = [kpabe.decrypt(cipher_text, secret_key) for cipher_text in ct] 
		# print 'lol', result
		# print storage['plain'][1:n+1]


		return storage

def serialize(s):
	storage = {}
	storage['n'] = s['n']
	storage['master_public_key'] = objectToBytes(s['master_public_key'], group)
	storage['master_key'] = objectToBytes(s['master_key'], group)
	storage['plain'] = objectToBytes(s['plain'], group)
	storage['cipher'] = objectToBytes(s['cipher'], group)

	return storage

def deserialize(storage):
	storage['n'] = storage['n']
	storage['master_public_key'] = bytesToObject(storage['master_public_key'], group)
	storage['master_key'] = bytesToObject(storage['master_key'], group)
	storage['plain'] = bytesToObject(storage['plain'], group)
	storage['cipher'] = bytesToObject(storage['cipher'], group)
	return storage


def getStorageSize(storage):
	public = {}
	public['master_public_key'] = objectToBytes(storage['master_public_key'], group)
	public['cipher'] = objectToBytes(storage['cipher'], group)
	public['n'] = storage['n']
	private = {}
	private['master_key'] = objectToBytes(storage['master_key'], group)
	# private['plain'] = objectToBytes(storage['plain'], group)

	return getsizeof(pickle.dumps(public)), getsizeof(pickle.dumps(private))


def generate_range(storage, q):
		# print storage['n'], q
		if (q>=storage['n']):
			print 'lol'
			return (1, 1+storage['n'])
		start_frame = random.randint(1, storage['n'] - q)
		# kac = KAC()
		# kac.n = storage['n']
		# kac.e_g1_g2 = storage['e_g1_g2']

		return (start_frame, start_frame+q)


# def extraction_time(storage, q_list):
# 	iterations = 1
# 	kpabe = KPabe(group)
# 	timings = []
# 	aggregate_size = []
# 	no_of_bits = len(list(bin(storage['n'])[2:]))+1  
# 	for q in q_list:
# 		timing = 0.0
# 		for i in xrange(iterations):
# 			more_than_equal, less_than = generate_range(storage, q)	 
# 			start = time.clock()
# 			policy = policy_less_than('A', less_than, no_of_bits) + " and " + policy_more_than_equal('A', more_than_equal, no_of_bits)
# 			secret_key = kpabe.keygen(storage['master_public_key'], storage['master_key'], policy)
# 			end = time.clock()
# 			timing += end-start
# 		timings.append((q, timing/iterations))
# 		aggregate_size.append((q, getsizeof(pickle.dumps(objectToBytes(secret_key, group)))))
# 	# print timings
# 	return timings, aggregate_size

def decryption_time(storage, q_list):
	iterations = 1
	timings = []
	aggregate_time = []
	aggregate_size = []
	no_of_bits = len(list(bin(storage['n'])[2:]))+1  
	kpabe = KPabe(group)
	for q in q_list:
		check = True
		timing = 0.0
		gen_timing = 0.0
		for i in xrange(iterations):
			more_than_equal, less_than = generate_range(storage, q)	 
			start = time.clock()
			policy = policy_less_than('A', less_than, no_of_bits) + " and " + policy_more_than_equal('A', more_than_equal, no_of_bits)
			secret_key = kpabe.keygen(storage['master_public_key'], storage['master_key'], policy)
			end = time.clock()
			gen_timing += end-start

			cipher_text = storage['cipher'][more_than_equal:less_than]
			plain_text = storage['plain'][more_than_equal:less_than]
			start = time.clock()
			result = [kpabe.decrypt(ct, secret_key) for ct in cipher_text]
			end = time.clock()
			timing+=end-start
			if (plain_text!=result):
				check = False
		aggregate_time.append((q, gen_timing/iterations))
		aggregate_size.append((q, getsizeof(pickle.dumps(objectToBytes(secret_key, group)))))
		if (check==True):
			timings.append((q, timing/iterations))
		else:
			timings.append((q, 'error'))
	return timings

if __name__ == "__main__":
	main()
# msmtDict = group.GetGeneralBenchmarks()
# print("<=== General Benchmarks ===>")
# print("Mul := ", msmtDict["Mul"])
# print("Div := ", msmtDict["Div"])
# print("Without: ", group.GetBenchmark("RealTime"))





