from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randbytes


def xor_strings(strng1, strng2):
	xord = [byte1 ^ byte2 for byte1, byte2 in zip(strng1, strng2)]
	return bytes(xord)

def encryption_oracle(plaintext):
	prefix = b"comment1=cooking%20MCs;userdata="
	suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
	filtered = plaintext.replace(';', '').replace('=', '')
	strng = prefix + filtered.encode('utf-8') + suffix
	padded = pad(strng, AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, iv)
	encrypted = cipher.encrypt(padded)
	return encrypted

def check_admin(encrypted):
	decipher = AES.new(key, AES.MODE_CBC, iv)
	decrypted = decipher.decrypt(encrypted)
	unpadded = unpad(decrypted, AES.block_size)
	if b";admin=true;" in unpadded:
		return True
	return False

def forge_admin():
	payloadEnc = '016bytes'*2 + 'dadminttruedcomm'
	suffixLen = len("comment1=cooking%20MCs;userdata=")
	payloadDec = b';admin=true;comm'
	encrypted = encryption_oracle(payloadEnc)
	xord = xor_strings(xor_strings(encrypted[2*AES.block_size:3*AES.block_size], b'dadminttruedcomm'), payloadDec)
	forged = encrypted[:2*AES.block_size] + xord + encrypted[3*AES.block_size:]
	return forged

if __name__ == '__main__':
	key = randbytes(AES.block_size)
	iv = randbytes(AES.block_size)
	test1 = 'Hack!;admin=true;whatelse'
	test2 = check_admin(encryption_oracle(test1))
	forged = forge_admin()
	result = check_admin(forged)
	print("\n---------- Cryptopals: Challenge 16 (Block Crypto) ----------\n")
	print("  We need to make a function which filters ';' and '=' characters, then prepends a prefix and appends a suffix to the suplied input plaintext, before encrypting it using AES-128-CBC and random key and IV. Another function decrypts the output from previous function and looks for the string ';admin=true;', returning True or False according to the result. We are able to forge an encrypted payload which decrypts to plaintext containing ';admin=true;':")
	print(f"\n\tLet's check that we are correctly filtering ';' and '=' characters:\n")
	print(f"\t\tInput:\t{test1}")
	print(f"\t\tResult:\t{test2}")
	print(f"\n\tLet's forge our payload for bitflipping attack, and check the result:\n")
	print(f"\t\tInput:\t{'016bytes'*2 + 'dadminttruedcomm'}")
	print(f"\t\tResult:\t{result}")
	