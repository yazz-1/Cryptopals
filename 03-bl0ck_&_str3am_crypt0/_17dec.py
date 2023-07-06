from base64 import b64decode
from random import randint, randbytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encryption():
	b64strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
	randIdx = randint(0, len(b64strings)-1)
	strng = b64decode(b64strings[randIdx])
	padded = pad(strng, AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	encrypted = cipher.encrypt(padded)
	return encrypted, padded

def padding_oracle(encrypted):
	decipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = decipher.decrypt(encrypted)
	try:
		unpadded = unpad(decrypted, AES.block_size)
	except ValueError:
			return False
	return True

def decrypt_block(block1, block2):
	plainbytes = b''
	iv_attack = block1
	padding = 0
	for i in range(len(iv_attack), 0, -1):
		padding += 1
		for byte in range(2**8):
			iv_attack = iv_attack[:i-1] + bytes([byte]) + iv_attack[i:]
			payload = iv_attack + block2
			check = padding_oracle(payload)
			if (check):
				if padding == 1:
					iv_attack2 = iv_attack[:-2] + bytes([iv_attack[-2]^1]) + bytes([iv_attack[-1]])
					payload2 = iv_attack2 + block2
					if not padding_oracle(payload2):
						continue
				plainbyte = padding ^ block1[i-1] ^ byte
				plainbytes = bytes([plainbyte]) + plainbytes
				iv_attack = bytearray(iv_attack)
				for k in range(1,padding+1):
					iv_attack[-k] = padding+1 ^ padding ^ iv_attack[-k]
				iv_attack = bytes(iv_attack)
				break
	return plainbytes

def padding_oracle_attack(encrypted):
	decrypted = b''
	blocks = [encrypted[i:i+AES.block_size:] for i in range(0, len(encrypted), AES.block_size)]
	for i in range(len(blocks)-1, 0, -1):
		decrypted = decrypt_block(blocks[i-1], blocks[i]) + decrypted
	decrypted = decrypt_block(iv, blocks[0]) + decrypted
	return decrypted

def main():
	encrypted, padded = encryption()
	decrypted = padding_oracle_attack(encrypted)
	print("\n---------- Cryptopals: Challenge 17 (Block & Stream Crypto) ----------\n")
	print("  We need to implement the best-known attack on modern block-cipher cryptography: the CBC padding oracle attack. We'll pad a randomly chosen string and we'll encrypt it using AES-128-CBC with both random key and IV. The key point is to exploit the information leakeage in the padding oracle (whether a ciphertext decrypts to well padded plaintext or not) so we can decrypt the message just by iterating some XOR operations. We decrypt each byte, starting at the end and going backwards. We bruteforce the nth byte at the (N-1)th block to decrypt de nth byte at the Nth block. One we get a valid response from the padding oracle, we calculate the corresponding plain byte and prepare the previously bruteforced bytes to decrypt to the next padding value. An edge case is when we are testing for 'padding = 1' while trying to decrypt the last block: we could get a valid padding with 2 different values, e.g. '\\x01' or '\\x02' if plain bytes were '\\x13\\x02\\x011'. To avoid this situation, we test if changing the penultimate byte too results in a valid padding or not: if it does then we have that real padding is '\\x01'; in other case we'll need to keep searching")
	print(f"\n\n\tPadded string:\t\t{padded}\n\n\tEncrypted message:\t{encrypted}\n\n\tDecrypted message:\t{decrypted}")

if __name__ == '__main__':
	key = randbytes(AES.block_size)
	iv = randbytes(AES.block_size)
	main()
	
	
	
	
	
	
	
	
