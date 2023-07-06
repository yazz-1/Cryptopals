import numpy as np
from collections import Counter
import math

np.seterr(divide='ignore', invalid='ignore')

def xor_single_byte(byteLst):
	posible_bytes = range(2**8)
	n = len(byteLst)
	results = []
	for byte in posible_bytes:
		xordStr = ''.join(chr(byte ^ byteLst[i]) for i in range(n))
		results.append([xordStr, byte])
	return results

def bhattacharyya(hist1, hist2):
  '''Calculates the Byattacharyya distance of two histograms.'''
# measures similarity of 2 given probability distributions; gives 0 if are identical

  def normalize(hist):
    return hist / np.sum(hist)
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

def main():
	hex_str = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
	kBest = 1
	bytelist = bytes.fromhex(hex_str)

	cands = xor_single_byte(bytelist)
	gue55 = english_score(cands)[:kBest]

	print("\n---------- Cryptopals: Challenge 3 (Basics) ----------\n")
	print('''  We need to XOR a hex encoded string against every possible byte. Later, we have to score each reasult as a piece of English text or no (we use Bhattacharyya distance and character frequency to achieve it):\n''')
	print(f"\tOur {kBest} best guess(es), Good Luck!! =) :\n")
	for i in range(kBest):
		score = gue55[i][0]
		decoded = gue55[i][1]
		byte = gue55[i][2]
		print(f"\t\t\t{i+1}.-Score: {score:.4f},  Byte: {byte},  Decrypted message: {decoded}")

if __name__ == '__main__':
	main()
