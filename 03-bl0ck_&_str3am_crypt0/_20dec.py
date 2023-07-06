#from subprocess import check_output as run
from Crypto.Cipher import AES
from random import randbytes
from base64 import b64decode
from collections import Counter
import numpy as np


def aes_ctr(strng):
	Nblocks = len(strng)//16 + 1
	result = b''
	blocks = [strng[k*block_size:k*block_size+AES.block_size] for k in range(Nblocks)] + [strng[-(len(strng)//block_size):]]
	for i in range(Nblocks):
		current_block = blocks[i]
		nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00' + bytes([i])+ b'\x00\x00\x00\x00\x00\x00\x00'
		cipher = AES.new(key, AES.MODE_ECB)
		keystream = cipher.encrypt(nonce)
		#print(keystream)
		for j in range(len(current_block)):
			xored = current_block[j]^keystream[j]
			result += bytes([xored])
	return result

def xor_single_byte(byteLst):
	posible_bytes = range(2**8)
	n = len(byteLst)
	results = []
	for byte in posible_bytes:
		xordStr = ''.join(chr(byte ^ byteLst[i]) for i in range(n))
		results.append([xordStr, byte])
	return results

def normalize(hist):
	return hist / np.sum(hist)

def bhattacharyya(hist1, hist2):
	'''Calculates the Byattacharyya distance of two histograms.'''
	# measures similarity of 2 given probability distributions; gives 0 if are identical
	return 1 - np.sum(np.sqrt(np.multiply(normalize(hist1), normalize(hist2))))

def english_score(lst):
	englishFreq = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182, 'A': 0.0651738, 'B': 0.0124248, 'C': 0.0217339, 'D': 0.0349835, 'E': 0.1041442, 'F': 0.0197881, 'G': 0.0158610, 'H': 0.0492888, 'I': 0.0558094, 'J': 0.0009033, 'K': 0.0050529, 'L': 0.0331490, 'M': 0.0202124, 'N': 0.0564513, 'O': 0.0596302, 'P': 0.0137645, 'Q': 0.0008606, 'R': 0.0497563, 'S': 0.0515760, 'T': 0.0729357, 'U': 0.0225134, 'V': 0.0082903, 'W': 0.0171272, 'X': 0.0013692, 'Y': 0.0145984, 'Z': 0.0007836}
	n = len(lst)
	scores = []
	for strng in lst:
		m = len(strng[0])
		known_freq = []
		sample_freq = []
		c = Counter(strng[0])
		for char, y in c.items():
			known_freq.append(englishFreq.get(char,0)) 
			sample_freq.append(y/m)
		score = bhattacharyya(known_freq,sample_freq)
		scores.append([score, strng[0], strng[1]])
	scores.sort(key=lambda x: x[0])
	return scores

def decrypting_attempt(encStrings):
	#primero creamos bytelists con la longitud de la string mas pequeña
	min_len = 100
	for str in encStrings:
		if len(str)<min_len:
			min_len = len(str)
		else:
			continue
	results = [bytes() for i in range(min_len)]
	for i in range(min_len):
		for j in range(len(encStrings)):
			results[i] = results[i] + bytes([encStrings[j][i]])
	#hacemos bruteforce contra el byte con que cada una de ellas se encrypta
	keystr3am = bytes()
	for result in results:
		cands = xor_single_byte(result)
		#calculamos el score de cada resultado y escogemos el mejor candidato
		gue55es = english_score(cands)
		idx = 0
		gue55 = gue55es[idx]
		while not gue55[1].isascii():
			idx += 1
			gue55 = gue55es[idx]
		keystr3am += bytes([gue55[2]])
	#unimos todos los candidatos para hallar la keystream mas probable
	return keystr3am

def main():
	#rem_file = run(['curl', '--silent', 'https://cryptopals.com/static/challenge-data/20.txt'], encoding='utf-8')
	#lines = rem_file.split('\n')
	fl = open('20enc.txt', 'r')
	b64_txt = fl.read()
	b64_strings = b64_txt.split('\n')
	decoded_strings = [b64decode(b64_strings[k]) for k in range(len(b64_strings))]
	encrypted_strings = []
	for j in range(len(b64_strings)):
		encrypted_strings = encrypted_strings + [aes_ctr(decoded_strings[j])]
	keystream = decrypting_attempt(encrypted_strings)
	for i in range(len(b64_strings)):
		print(i, 'ori: ', decoded_strings[i].decode('utf-8'))
		print(i, 'dec: ', ''.join([chr(byte1^byte2) for byte1, byte2 in zip(encrypted_strings[i], keystream)]), '\n')
	return 0

if __name__ == '__main__':
	block_size = AES.block_size
	key = randbytes(block_size)
	np.seterr(divide='ignore', invalid='ignore')
	main()