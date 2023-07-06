#from subprocess import check_output as run
from Crypto.Cipher import AES
from _06dec import *

#rem_file = run(['curl', '--silent', 'https://cryptopals.com/static/challenge-data/8.txt'], encoding='utf-8')

def block_collision(byteLst):
	chunks = get_chunks(byteLst, 16)
	n = len(chunks)
	for i in range(n):
		for j in range(i+1,n):
			if chunks[i] == chunks[j]:
				indexes = [i, j]
				equal_chunks = [chunks[i], chunks[j]]
				return [True, indexes, equal_chunks]
			else:
				continue
	
	return [False, None, None]

def collisions_check(linesBytes):
	res = [None, False, None, None]
	for i in range(len(linesBytes)):
		line = linesBytes[i]
		collision = block_collision(line)
		if collision[0] == True:
			res = [i, collision]
			return res
		else:
			continue
	return res

def main():
	fl = open('08enc.txt', 'r')
	txt_hex = fl.read()
	txt_bytes = bytes.fromhex(txt_hex)

	lines_hex = txt_hex.split('\n')
	lines_bytes = [bytes.fromhex(line) for line in lines_hex]

	coll = collisions_check(lines_bytes)

	print("\n---------- Cryptopals: Challenge 8 (Basics) ----------\n")
	print("  We need to detect wich ciphertext (each line in file) has been encrypted using AES-128-ECB algorithm. This can be achieve because of weaknesses of the algorithm itself: the same input block results in the same output block. On the other hand, the probability of 2 blocks 128-bits length to collide is really remote (the number of all possible blocks is 2^128!!). So we can assert it's been AES-128-ECB encrypted if we encounter 2 equal blocks in any of the ciphertexts:\n")

	print(f"\tWe found a match!! =):\n\n\t\tLine: {coll[0]}\n\n\t\tCiphertext: {lines_hex[coll[0]]}\n\n\t\tBlock {coll[1][1][0]}: {coll[1][2][0]}\n\n\t\tBlock {coll[1][1][1]}: {coll[1][2][1]}")

if __name__ == '__main__':
	main()
