import math
import random
import time
from functools import reduce
import numpy as np
from fractions import Fraction
from mpmath import *

def add(x, y, carry=0, pad=False):
	result = []
	if pad: pad(x, y)
	for a, b in list(zip(x, y)):
		s, c_new = three_bit_adder(a, b, carry)
		result.append(s)
		carry = c_new
	return result

def pad(l1, l2):
	lx, ly = len(l1), len(l2)
	final_len = lx + 1 if lx >= ly else ly + 1
	l1 += list(np.zeros(final_len-lx, dtype=int))
	l2 += list(np.zeros(final_len-ly, dtype=int))

def three_bit_adder(a, b, c):
	s = _xor(_xor(a, b), c)
	c_out = _xor(_xor(_and(a,b), _and(b,c)), _and(c,a))
	return s, c_out

def sub(x, y):
	lx, ly = len(x), len(y)
	pad(x, y)
	y_flip = [_not(b) for b in y]
	return add(x, y_flip, carry=1)

def _xor(c_1, c_2):
	return c_1+c_2

def _and(c_1, c_2):
	return c_1 * c_2

def _not(c):
	return c+1

def _or(c_1, c_2):
	return _not(_and(_not(c_1), _not(c_2)))

def is_zero(c):
	return _not(reduce(_or, c))

def search(D, key):
	matches = [is_zero(sub(entry, key)) for entry in D]
	return reduce(_or, matches)

def dot(x, y):
	return sum([i * j for i, j in zip(x, y)])

def mod_2(a):
	print(math.floor(a/mpf(2)))
	return a - mpf(2) * mpf(math.floor(a / mpf(2)))

def reciprocal(a, n_bits):
	denom = mpf(2**n_bits)
	num = round(1/mpf(a) * denom)
	return mpf(num) / mpf(denom)

def lazy_encrypt(n, num_bits=4):
	return [(n & (1 << b)) >> b for b in range(num_bits)]

def lazy_decrypt(c):
	bits = list(map(lambda x: x %2, c))
	result = 0
	for i in range(len(c)):
		result += 2**i * c[i]
	return result

def she_keygen(ld):
	sec_params = {'N': ld, 'P': ld**2, 'Q': ld**5}
	s_key = (random.getrandbits(sec_params['P']-1) * 2) + 1
	p_key = [she_sk_encrypt_bit(s_key, 0, sec_params) for i in range(ld)]
	return s_key, p_key, sec_params

def she_sk_encrypt_bit(s_key, msg, sec_params):
	q = random.getrandbits(sec_params['Q']) 
	n = random.getrandbits(sec_params['N']-1) * 2
	m_prime = msg + n
	return q * s_key + m_prime

def she_sk_encrypt(s_key, msg, n_bits, sec_params):
	return encrypt_bits(msg, 
						lambda b: she_sk_encrypt_bit(s_key, b, sec_params),
						n_bits)

def she_pk_encrypt_bit(p_key, msg):
	result = msg
	for k in p_key:
		if random.randint(0,1) == 1:
			result += k
	return result

def she_pk_encrypt(s_key, msg, n_bits):
	return encrypt_bits(msg, 
						lambda b: she_pk_encrypt_bit(s_key, b),
						n_bits)

def she_decrypt_bit(s_key, c_text):
	return (c_text % s_key) % 2 

def she_decrypt(s_key, c_texts):
	return decrypt_bits(c_texts, lambda c: she_decrypt_bit(s_key, c))

def encrypt_bits(N, enc_func, n_bits):
	bits = list(reversed(bin(N)[2:]))
	[bits.append('0') for b in range(n_bits - len(bits))]
	return [enc_func(int(bit)) for bit in bits]

def decrypt_bits(c_texts, dec_func):
	bits = reversed([dec_func(c) for c in c_texts])
	N = 0
	for bit in bits:
		N = (N << 1) | bit
	return N	

def fhe_keygen(ld):
	alpha = math.floor(ld / math.log(ld))
	beta = math.ceil(ld ** 5 * math.log(ld))
	prec = ld**2
	mp.prec = prec
	sk, pk, sec_params = she_keygen(ld)
	indices = np.random.choice(range(0, beta), alpha)
	s = np.zeros(beta)
	s[indices] = 1
	y = []
	for i in range(beta):	
		num = random.getrandbits(prec+1)
		denom = 2**prec
		y.append(mpf(num)/mpf(denom))
	# y = np.random.uniform(low=0, high=2, size=beta)
	subset_sum = reciprocal(sk, prec)
	offset = (dot(s, y) % 2) - subset_sum
	# print("Old offset", offset)
	y[indices[0]] = (y[indices[0]] - offset) % 2
	# print("New offset", np.dot(s, y) % 2 - 1/sk)
	return (sk, s), (pk, y), sec_params
	# return np.dot(s, y) % 2 - 1/sk > 0.0000001
	
def fhe_sk_encrypt_bit(s_key, msg, sec_params, y):
	c = she_sk_encrypt_bit(s_key, msg, sec_params)
	z_init = [mpf(c) * mpf(i) for i in list(y)]
	z = [mod_2(i) for i in z_init]
	return c, z

def fhe_sk_encrypt(s_key, msg, sec_params, y, n_bits):
	return encrypt_bits(msg, 
					lambda m: fhe_sk_encrypt_bit(s_key, m, sec_params, y), 
					n_bits)

def fhe_pk_encrypt_bit(p_key, msg, y):
	c = she_pk_encrypt_bit(p_key, msg)
	z_init = [mpf(c) * mpf(i) for i in list(y)]
	z = [mod_2(i) for i in z_init]
	return c, z

def fhe_pk_encrypt(p_key, msg, y, n_bits):
	return encrypt_bits(msg, 
					lambda m: fhe_pk_encrypt_bit(p_key, m, y), 
					n_bits)

def fhe_decrypt_bit(c_text, s):
	return (c_text[0] & 1) ^ (math.floor(dot(c_text[1], s)) & 1)

def fhe_decrypt(c_text, s):
	return decrypt_bits(c_text, lambda c: fhe_decrypt_bit(c, s))

def test_encrypt_decrypt(n):
	print(lazy_decrypt(lazy_encrypt(n, 5)))
	print(lazy_decrypt(lazy_encrypt(n, 8)))
	print(lazy_decrypt(lazy_encrypt(n, 4)))

def test_search():
	D = list(np.random.randint(1, 10, 5))
	print("Database: ", D)
	in_key = D[1]
	print("In Key: ", in_key)
	in_key = lazy_encrypt(in_key)
	print("Out Key: ", 11)
	out_key = lazy_encrypt(11)
	enc_D = [lazy_encrypt(key) for key in D] 
	print("Encrypted Database: ", enc_D)
	print("Searching for present key, should be odd")
	print(search(enc_D, in_key))
	print("Searching for absent key, should be even")
	print(search(enc_D, out_key))

def test_she():
	msg = 25
	n_bits = 8
	s_key, p_key, sec_params = she_keygen(5)
	sk_c = she_sk_encrypt(s_key, msg, n_bits, sec_params)
	pk_c = she_pk_encrypt(p_key, msg, n_bits)
	print("Number of bits in encryption, should be", n_bits)
	print(len(sk_c))
	print(len(pk_c))
	print("Decrypted message, should be", msg)
	print(she_decrypt(s_key, sk_c))
	print(she_decrypt(s_key, pk_c))

def test_she_add():
	m, n = 2, 3
	n_bits = 8
	s_key, p_key, sec_params = she_keygen(10)
	c_m = she_sk_encrypt(s_key, m, n_bits, sec_params)
	c_n = she_sk_encrypt(s_key, n, n_bits, sec_params)
	enc_result = add(c_m, c_n)
	print(len(enc_result))
	dec_result = she_decrypt(s_key, enc_result)
	print("Decrypted result, should be", m+n)
	print(dec_result)


if __name__ == '__main__':
	m = 1
	ld = 6
	bits = 1
	start = time.time()
	(sk, s), (pk, y), sec_params = fhe_keygen(ld)
	end = time.time()
	print("Key generation took: " + str(end-start) + " seconds.")
	start = time.time()
	c = fhe_sk_encrypt(sk, m, sec_params, y, bits)
	end = time.time()
	print("Secret key encryption took: " + str(end-start) + " seconds.")
	start = time.time()
	d = fhe_decrypt(c, s)
	end = time.time()
	print("Decryption took: " + str(end-start) + " seconds.")
	print("Message decrypted should be", m)
	print(d)
