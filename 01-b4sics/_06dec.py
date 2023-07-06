#from subprocess import check_output as run
from base64 import b64decode
from _03dec import *
from _05dec import *

#rem_file = run(['curl', '--silent', 'https://cryptopals.com/static/challenge-data/6.txt'], encoding='utf-8')

def hamming_distance(chunk1, chunk2):
	dist = 0
	for i in range(len(chunk1)): 
		xored_byte = chunk1[i] ^ chunk2[i]
		dist += f"{xored_byte:b}".count('1')
	return dist

def normalized_hamming_distance(chunk1, chunk2):
	return hamming_distance(chunk1, chunk2)/len(chunk1)

def keysize_guess(byteLst, kSizes):
	keysDist = []
	for k in kSizes:
		chunk1 = byteLst[:k]
		chunk2 = byteLst[k:2*k]
		chunk3 = byteLst[2*k:3*k]
		chunk4 = byteLst[3*k:4*k]
		dist1 = normalized_hamming_distance(chunk1, chunk2)
		dist2 = normalized_hamming_distance(chunk1, chunk3)
		dist3 = normalized_hamming_distance(chunk1, chunk4)
		dist4 = normalized_hamming_distance(chunk2, chunk3)
		dist5 = normalized_hamming_distance(chunk2, chunk4)
		dist6 = normalized_hamming_distance(chunk3, chunk4)
		dist = (dist1 + dist2 + dist3 + dist4 + dist5 + dist6)/6
		keysDist.append([dist, k])
	keysDist.sort(key=lambda x: x[0])
	return keysDist

def get_chunks(byteLst,kSize):
	n = len(byteLst)
	q = n // kSize
	r = n % kSize
	chunks = []
	for i in range(q):
		chunks.append(byteLst[i*kSize:(i+1)*kSize])
	if r == 0:
		return chunks
	else:
		chunks.append([q*kSize, q*kSize + r])
		return chunks


def transpose_chunks(chunks):
	n = len(chunks)
	big = len(chunks[0])
	small = len(chunks[-1])
	new = [[] for k in range(big)]
	for i in range(small):
		for j in range(n):
			new[i].append(chunks[j][i])
	for i in range(small, big):
		for j in range(n-1):
			new[i].append(chunks[j][i])
	return new

def main():
	fl = open('06enc.txt', 'r')
	txt_b64 = fl.read()
	txt_bytes = b64decode(txt_b64)

	keysizes = range(2, 41)
	keysize_cand = keysize_guess(txt_bytes, keysizes)[0]
	keysize = keysize_cand[1]

	chunk5 = get_chunks(txt_bytes, keysize)	
	transposed = transpose_chunks(chunk5)

	xor_keys = []
	for chnk in transposed:
		cands = xor_single_byte(chnk)
		guess = english_score(cands)[0]
		xor_key = guess[2]
		xor_keys.append(xor_key)

	decrypted_bytes = repeating_key_xor(txt_bytes, xor_keys)
	decrypted = ''.join(chr(byte) for byte in decrypted_bytes)
	key = ''.join(chr(k) for k in xor_keys)

	print("\n---------- Cryptopals: Challenge 6 (Basics) ----------\n")
	print("  We need to break a repeating key XOR text. We use the Hamming distance to guess the keysize, and some of our functions previously coded to achieve it. Block chunking and transposing results from repeating key xor mechanism (every keysize 'multiple' byte is xored against the same byte which in fact is an equivalent relation and so produces a quotient set):\n")
	print(f"\t\tXOR Repeating Key: {key}\n\n\t\tDecrypted message:\n\n{decrypted}")

if __name__ == '__main__':
	main()
