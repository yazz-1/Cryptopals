from Crypto.Cipher import AES

def pkcs7_unpad(padded):
	try:
		if len(padded) % blockSize != 0:
			raise ValueError
	except ValueError:
		print(f"\tException! Plaintext is not an even multiple of 16 bytes block. Input: {padded}\n")
		return
	padding = padded[-1] * bytes([padded[-1]])
	try:
		if padding != padded[-padded[-1]:]:
			raise ValueError
	except ValueError:
		print(f"\tException! Padding value is incorrect (possibly padding value larger than padding length or padding values are differents). Input: {padded}\n")
		return
	unpadded = padded[:-padded[-1]]
	try:
		if unpadded.decode('utf-8').isprintable() != True:
			raise ValueError
	except ValueError:
		print(f"\tException! Padding is incorrect (possibly padding larger than padding value). Input: {padded}\n")
		return
	return unpadded

def main():
	test1 = b"ICE ICE BABY\x04\x04\x04\x04"
	test2 = b"ICE ICE BABY\x05\x05\x05\x05"
	test3 = b"ICE ICE BABY\x01\x02\x03\x04"
	test4 = b"ICE ICE BABY\x03\x03\x03\x03"
	test5 = b"ICE ICE BABY\x03\x03\x03"
	print("\n---------- Cryptopals: Challenge 15 (Block Crypto) ----------\n")
	print("  We need to make a function which checks if any plaintext input has a correct PKCS#7 padding, and if so, returns the unpadded plaintext:\n")
	print(f"\tTest inputs:\n\n\t\t{test1} CORRECT\n\t\t{test2} INCORRECT\n\t\t{test3} INCORRECT\n\t\t{test4} INCORRECT\n\t\t{test5} INCORRECT\n")
	pkcs7_unpad(test2), pkcs7_unpad(test3), pkcs7_unpad(test4), pkcs7_unpad(test5)
	print(f"\tSuccesfully unpadded!\n\tPadded text: {test1}\n\tUnpadded text: {pkcs7_unpad(test1)}")

if __name__ =='__main__':
	blockSize = AES.block_size
	main()