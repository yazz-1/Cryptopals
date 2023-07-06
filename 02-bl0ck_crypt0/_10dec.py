from subprocess import check_output as run
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from _09dec import *

def xor_strings(strng1, strng2):
	xordStrng = b''
	for byte1, byte2 in zip(strng1, strng2):
		xord = byte1 ^ byte2
		xordStrng += bytes([xord])
	return xordStrng

def cbc_encrypt(plaintext, key, iv):
	blockSize = AES.block_size
	padded = pkcs7_pad(plaintext, blockSize)
	blocks = [padded[i:i+blockSize] for i in range(0, len(plaintext), blockSize)]
	cipher = AES.new(key, AES.MODE_ECB)
	
	result = b''
	prevBlock = iv
	for block in blocks:
		xord = xor_strings(prevBlock, block)
		encrypted = cipher.encrypt(xord)
		prevBlock = encrypted
		result += encrypted
	return result

def cbc_decrypt(encrypted, key, iv):
	decipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = decipher.decrypt(encrypted)
	unpadded = unpad(decrypted, AES.block_size)
	return unpadded
def main():
	base64text = run(['curl', '--silent', 'https://cryptopals.com/static/challenge-data/10.txt'], encoding='utf-8')
	encrypted = b64decode(base64text)
	key = b'YELLOW SUBMARINE'
	iv = bytes([0]) * 16
	decrypted = cbc_decrypt(encrypted, key, iv)
	print("\n---------- Cryptopals: Challenge 10 (Block Crypto) ----------\n")
	print("  We need to implement AES-128-CBC encryption/decryption using AES-128-ECB and XOR. On success, it must be able to decrypt the base64 encoded file given using an initialization vector of all ASCII '0' and the key 'YELLOW SUBMARINE'. Then we can try to encrypt and decrypt everything we want to with our own key:\n")
	print(f"\tInitialization vector:\t{iv}\n\tKey:\t\t\t{key}\n\tDecrypted message:\n\n{decrypted.decode('utf-8')}")
	print("-------------------------------------------------------------\n")
	our_plaintext = b'Hola caracola!' * 5
	our_key = pkcs7_pad(b'Hola caraculo!', 16)
	our_iv = bytes([3]) * 16
	our_encrypted = cbc_encrypt(our_plaintext, our_key, our_iv)
	our_decrypted = cbc_decrypt(our_encrypted, our_key, our_iv)
	print("  Now we are going to use it to encode and decode our own plaintext using our own IV and key:\n")
	print(f"\n\tPlaintext:\t\t{our_plaintext.decode('utf-8')}\n\n\tEncrypted text:\t\t{our_encrypted}\n\n\tInitialization vector:\t{our_iv}\n\tKey:\t\t\t{our_key}\n\tDecrypted message:\t{our_decrypted.decode('utf-8')}")

if __name__ == '__main__':
	main()
