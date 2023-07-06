from base64 import b64decode
from Crypto.Cipher import AES


def aes_ctr(strng):
	Nblocks = len(strng)//16 + 1
	result = b''
	blocks = [strng[k*AES.block_size:k*AES.block_size+AES.block_size] for k in range(Nblocks)] + [strng[-(len(strng)//AES.block_size):]]
	for i in range(Nblocks):
		current_block = blocks[i]
		nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00' + bytes([i])+ b'\x00\x00\x00\x00\x00\x00\x00'
		cipher = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)
		keystream = cipher.encrypt(nonce)
		for j in range(len(current_block)):
			xored = current_block[j]^keystream[j]
			result += bytes([xored])
	return result

def main():
	encrypted1 = b64decode(b64string)
	decrypted = aes_ctr(encrypted1)
	encrypted2 = aes_ctr(decrypted)
	print("\n---------- Cryptopals: Challenge 18 (Block & Stream Crypto) ----------\n")
	print("  We start working with a new AES mode of operation: CTR. The way it operates is: we encrypt a 16 bytes (block size) counter using AES encryption in ECB mode using the given key ('YELLOW SUBMARINE') and we XOR the plaintext block against the encrypted result; then we keep modifying the counter, encrypting it and XORing with the rest of the blocks. This mode of operation doesn't require to pad the plaintext")
	print(f"\n\n\tDecoded b64 bytes:\t{encrypted1}\n\n\tDecrypted message:\t{decrypted}\n\n\tRe-encrypted message:\t{encrypted2}")

if __name__ == '__main__':
	b64string = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
	main()
