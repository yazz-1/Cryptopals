from _03dec import *
#from subprocess import check_output as run
import numpy as np

nan = np.nan

#rem_file = run(['curl', '--silent', 'https://cryptopals.com/static/challenge-data/4.txt'], encoding='utf-8')
#lines = rem_file.split('\n')
fl = open('04enc.txt', 'r')
txt = fl.read()
lines = txt.split('\n')

gue55es = []

for line in lines:
	candidates = xor_single_byte(bytes.fromhex(line))
	gue55 = english_score(candidates)
	gue55es.append(gue55)

best = [10, '', nan]

for gue in gue55es:
	for e in gue:
		if ((e[0] < best[0]) & (e[0] != nan)):
			best = e

print("\n---------- Cryptopals: Challenge 4 (Basics) ----------\n")
print("  We need to XOR a bunch of ~300 hex encoded string against every possible byte, choose the results with best scores for every line and finally to compare them all (we use the functions coded in the previous challenge to achieve it). The one with the best score should be the decrypted message:\n")
print(f"Score: {best[0]}\tByte: {best[2]}\tDecrypted message: {best[1]}")
