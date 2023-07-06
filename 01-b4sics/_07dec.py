from base64 import b64decode
from Crypto.Cipher import AES
#from subprocess import check_output as run

#rem_file = run(['curl', '--silent', 'https://cryptopals.com/static/challenge-data/7.txt'], encoding='utf-8')

def ecb_decrypt(txtBytes, keyBytes):
	decipher = AES.new(keyBytes, AES.MODE_ECB)
	decrypted = decipher.decrypt(txtBytes).decode('utf-8')
	return decrypted

def main():
	fl = open('07enc.txt', 'r')
	txt_b64 = fl.read()
	txt_bytes = b64decode(txt_b64)

	key = "YELLOW SUBMARINE"
	key_bytes = key.encode('utf-8')

	decrypted = ecb_decrypt(txt_bytes, key_bytes)
		
	print("\n---------- Cryptopals: Challenge 7 (Basics) ----------\n")
	print("  We need to decrypt a base64 encoded file using AES-128-EBC algorithm with the key 'YELLOW SUBMARINE'. We'll use cryptodome library:\n")
	print(f"\t\tDecrypted message:\n\n{decrypted}")

if __name__ == '__main__':
	main()
