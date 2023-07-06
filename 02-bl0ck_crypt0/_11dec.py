from random import randbytes, randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def random_key():
	return randbytes(16)

def ecb_encryption(plaintext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	padded = pad(plaintext, AES.block_size)
	encrypted = cipher.encrypt(padded)
	return encrypted

def cbc_encryption(plaintext, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	padded = pad(plaintext, AES.block_size)
	encrypted = cipher.encrypt(padded)
	return encrypted

def encryption_oracle(plaintext):
	randLen = randint(5, 10)
	suffix = randbytes(randLen)
	prefix = randbytes(randLen)
	modified = prefix + plaintext + suffix
	key = random_key()
	iv = randbytes(AES.block_size)
	randAlg = randint(1, 2)
	if randAlg == 1:
		mode = "ECB mode selected!!"
		encrypted = ecb_encryption(modified, key)
	if randAlg == 2:
		mode = "CBC mode selected!!"
		encrypted = cbc_encryption(modified, key, iv)
	return encrypted, mode

def ecb_cbc_detect(encrypted):
	blocks = [encrypted[i:i+AES.block_size] for i in range(0, len(encrypted), AES.block_size)]
	for i in range(len(blocks)):
		for j in range(i+1, len(blocks)):
			if blocks[i] == blocks[j]:
				return "ECB MODE detected!!"
	return "CBC mode inferred!!"

def main():
	plaintext = b"Bartolo dice miau" * 50
	encrypted, mode = encryption_oracle(plaintext)
	detected = ecb_cbc_detect(encrypted)
	print("\n---------- Cryptopals: Challenge 11 (Block Crypto) ----------\n")
	print("  First we need to code a function which generates a random key (16 bytes). Then we make an encryption oracle which encrypts randomly using ECB or CBC cipher block mode. Finally we make a function which can guess if some ciphertext has been encrypted using ECB or CBC mode:\n")
	print(f"\tOur plaintext is:\t{plaintext.decode('utf-8')}\n\n\t--> {mode}\n\n\t--> {detected}")

if __name__ == '__main__':
	main()
