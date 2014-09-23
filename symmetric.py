from kac_tree import KAC_Tree
from binary_tree import Node as HashTree
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from hashlib import sha256
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
import time, json, pickle, os, random, csv, copy

group = PairingGroup('SS512')

list_n = [2**i for i in xrange(128)]
timings = []


# iterations = max(1024/n, 1024)
key = group.random(G1)
plain = group.random(ZR)
start = time.clock()
for i in xrange(2 ** 16):
	key*=key
end = time.clock()
timings.append(end-start)

start = time.clock()
for i in xrange(2 ** 16):
	plain*=plain
end = time.clock()
timings.append(end-start)

print timings
