from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randbytes, randint


def encryption_oracle(plaintext):
	suffix = b'Esto es lo que hay que desencriptar!!' * 2
	cipher = AES.new(key, AES.MODE_ECB)
	padded = pad(prefix + plaintext + suffix, blockSize)
	encrypted = cipher.encrypt(padded)
	return encrypted

def get_prefix_length():
	payload1, payload2 = b'', b'A'
	encrypted1 = encryption_oracle(payload1)
	encrypted2 = encryption_oracle(payload2)
	j = 0
	for i in range(0, len(encrypted1), blockSize):
		if encrypted1[i:i + blockSize] == encrypted2[i:i + blockSize]:
			j += 1
			continue
		break

	newPayload, prevPayload = b'A', b''
	newEncrypted, prevEncrypted = encryption_oracle(newPayload), encryption_oracle(prevPayload)
	while prevEncrypted[j*blockSize:(j+1)*blockSize] != newEncrypted[j*blockSize:(j+1)*blockSize]:
		newPayload += b'A'
		prevPayload += b'A'
		newEncrypted = encryption_oracle(newPayload)
		prevEncrypted = encryption_oracle(prevPayload)
	
	prefixLen = j*blockSize + (blockSize - len(prevPayload))
	return prefixLen

def get_suffix_length(prefixLen):
	prevPayload = b''
	newPayload = b'A'
	prevEncrypted, newEncrypted = encryption_oracle(prevPayload), encryption_oracle(newPayload)
	prevLen, newLen = len(prevEncrypted), len(newEncrypted)
	while prevLen == newLen:
		newPayload += b'A'
		prevPayload += b'A'
		newLen = len(encryption_oracle(newPayload))
	suffixLen = prevLen - len(newPayload) - prefixLen
	return suffixLen

def decrypt_byte(prefixLen, decrypted):
	payloadLen = (blockSize - (prefixLen + len(decrypted)) % blockSize) - 1
	payload = b'A' * payloadLen
	encrypted = encryption_oracle(payload)[:prefixLen + payloadLen + len(decrypted) + 1]
	results = {}
	for byte in range(2**8):
		newPayload = payload + decrypted + bytes([byte])
		newEncrypted = encryption_oracle(newPayload)[:prefixLen + payloadLen + len(decrypted) + 1]
		results[newEncrypted] = bytes([byte])
	
	return results.get(encrypted, b'0')
	
def suffix_decrypt():
	prefixLen = get_prefix_length()
	suffixLen = get_suffix_length(prefixLen)
	decrypted = b''
	for i in range(suffixLen):
		decrypted += decrypt_byte(prefixLen, decrypted)
		print(f"\t\t{decrypted}")
	return decrypted

def main():
	prefix_len = get_prefix_length()
	suffix_len = get_suffix_length(prefix_len)
	print("\n---------- Cryptopals: Challenge 14 (Block Crypto) ----------\n")
	print("  We need to make a function which prepends an unknown prefix of unknown length, and appends an unknown suffix to plaintext before encrypting it with a random key. Then we need to decrypt the suffix:\n")
	print(f"\tPrefix length: {prefix_len}")
	print(f"\tSuffix length: {suffix_len}\n")
	print(f"\tDecrypting...\n")
	decrypted = suffix_decrypt()
	print(f"\n\tDecrypted plaintext suffix is: {decrypted.decode('utf-8')}")

if __name__ == '__main__':
	key = randbytes(16)
	blockSize = AES.block_size
	prefix = randbytes(1) * randint(1,3*blockSize)
	main()