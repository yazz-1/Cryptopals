from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes
from base64 import b64decode


def ecb_encryption(plaintext, key):
	suffixB64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" \
			"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" \
			"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" \
			"YnkK"
	suffix = b64decode(suffixB64)
	modified = plaintext + suffix
	padded = pad(modified, AES.block_size)
	cipher = AES.new(key, AES.MODE_ECB)
	encrypted = cipher.encrypt(padded)
	return encrypted

def get_blocksize(key):
	payload = b''
	initLen = len(ecb_encryption(payload, key))
	lastLen = len(ecb_encryption(payload, key))
	while lastLen == initLen:
		payload += b'A'
		encrypted = ecb_encryption(payload, key)
		lastLen = len(encrypted)
	return lastLen - initLen

def ecb_cbc_detect(encrypted):
	blocks = [encrypted[i:i+AES.block_size] for i in range(0, len(encrypted), AES.block_size)]
	for i in range(len(blocks)):
		for j in range(i+1, len(blocks)):
			if blocks[i] == blocks[j]:
				return "ECB MODE detected!!"
	return "CBC mode inferred!!"

def ecb_decrypt_byte(decrypted, key):
	blockSize = AES.block_size
	fillingLen = blockSize - ((len(decrypted) % blockSize) + 1)
	filling = b"A" * fillingLen
	initPayload = filling
	payloadLen = len(decrypted) + fillingLen + 1
	block = ecb_encryption(initPayload, key)[:payloadLen]
	results = {}
	for byte in range(2**8):
		payload = filling + decrypted + bytes([byte])
		blockProbe = ecb_encryption(payload, key)[:payloadLen]
		results[blockProbe] = byte
	return bytes([results.get(block, 0)])
	

def ecb_decrypt_suffix(key):
	unknownLen = len(ecb_encryption(b'', key))
	blockSize = get_blocksize(key)
	print(f"\tBlock size detected: {blockSize}")
	modeRes = ecb_cbc_detect(ecb_encryption(b'Hola caracola'*50, key))
	if "CBC" in modeRes:
		print("\tNot ECB mode detected!! Exiting...")
		return
	if "ECB" in modeRes:
		print(f"\tCipher block mode detected: ECB\n")
		decrypted = b''
		print(f"Decrypting...\n")
		for i in range(unknownLen):
			byte = ecb_decrypt_byte(decrypted, key)
			decrypted += byte
			print(f"\tByte {i}: {decrypted}")
	return decrypted

def main():
	key = randbytes(16)
	print("\n---------- Cryptopals: Challenge 12 (Block Crypto) ----------\n")
	print("  First we need to code a function which generates a random key (16 bytes) and encrypts data using it with AES-128-ECB. Before encrypting the supplied plaintext is appended with an unknown string. Finally, we write another function which can decrypts the unknown string using specially crafted inputs and comparing their encrypted results, after checking that 1st function is actually using AES-128-ECB and getting block size:\n")
	decrypted = ecb_decrypt_suffix(key)
	print(f"\n\tDecrypted text:\n\n{decrypted.decode('utf-8')}")

if __name__ == '__main__':
	main()
