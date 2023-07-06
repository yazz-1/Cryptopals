def pkcs7_pad(plaintext, blockSize):
	n = len(plaintext)
	r = n % blockSize
	padValue = blockSize - r
	padding = bytes([padValue]) * padValue
	return plaintext + padding

def main():
	test = b"YELLOW SUBMARINE"
	testPadded = b"YELLOW SUBMARINE\x04\x04\x04\x04"
	padded = pkcs7_pad(test, 20)
	print("\n---------- Cryptopals: Challenge 9 (Block Crypto) ----------\n")
	print("  We need to code a function which pads any plaintext to the desired block size (in bytes) using PKCS#7 scheme:\n")
	print(f"\tPlaintext:\t\t{test}\n\n\tExpected result:\t{testPadded}\n\tOur padded text:\t{padded}")

if __name__ == '__main__':
	main()
