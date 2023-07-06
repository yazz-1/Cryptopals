from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from random import randbytes


def parse_cookie(cookie):
	profile = {}
	pairs = cookie.split('&')
	for pair in pairs:
		key, value = pair.split('=')
		profile[key] = value
	return profile

def profile_for(email):
	email = email.replace('&', '').replace('=', '')
	uid = 0
	uid += 1
	cookie = 'email=' + email + '&uid=' + str(uid) + '&role=user'
	profile = parse_cookie(cookie)
	return cookie, profile

def profile_encryption(cookie):
	cipher = AES.new(key, AES.MODE_ECB)
	padded = pad(cookie.encode('utf-8'), AES.block_size)
	encrypted = cipher.encrypt(padded)
	return encrypted

def profile_decryption(encrypted):
	decipher = AES.new(key, AES.MODE_ECB)
	decrypted = decipher.decrypt(encrypted)
	unpadded = unpad(decrypted, AES.block_size)
	profile = parse_cookie(unpadded.decode('utf-8'))
	return unpadded, profile

def pwn_to_admin():
	payload1 = ''
	email1 = payload1 + '@protonmail.com'
	profile1 = profile_for(email1)
	encrypted1 = profile_encryption(profile1[0])
	
	prevLen = len(encrypted1)
	newLen = prevLen
	while newLen == prevLen:
		payload1 += 'A'
		email1 = payload1 + '@protonmail.com'
		profile1 = profile_for(email1)
		encrypted1 = profile_encryption(profile1[0])
		newLen = len(encrypted1)
	blockSize = newLen - prevLen
	payloadLen = len(payload1)
	
	payload2 = 'A' * (payloadLen + len('user'))
	email2 = payload2 + '@protonmail.com'
	profile2 = profile_for(email2)
	encrypted2 = profile_encryption(profile2[0])
	
	payload3 = 'A'*(blockSize - len('email=')) + 'admin' + bytes([11]).decode('utf-8')*11
	email3 = payload3 + '@protonmail.com'
	profile3 = profile_for(email3)
	encrypted3 = profile_encryption(profile3[0])
	
	block1 = encrypted2[:-blockSize]
	block2 = encrypted3[blockSize:2*blockSize]
	crafted = block1 + block2
	
	return profile_decryption(crafted)

def main():
	print("\n---------- Cryptopals: Challenge 13 (Block Crypto) ----------\n")
	print("  We need to make a function which creates a cookie from a supplied email account, and encrypts it (filtering '&' and '=' so we can't forge and admin profile). Then, we have to craft a ciphertext which decrypts to an admin profile:\n")
	print("\tFirst, let's check that we are correctly filtering '=' and '&' in our profile_for('email') function:\n")
	wrong = profile_for('wrong=mail@gma&il.com')
	print(f"\t\tInput: wrong=mail@gma&il.com\n\t\tCookie: {wrong[0]}\n\t\tProfile: {wrong[1]}")
	print("\n\tLet's craft a ciphertext by pasting 2 chunks. The first one must be all blocks but the last one from the encrypted cookie we get with a payload designed to force the last block being just the 'user' part of the cookie. The second one must be a block which only contains the word 'admin' and its respective padding (11 bytes of value 11):\n")
	print("\tGenerating payload... Admin profile succesfully created!")
	print(f"\n\t\tAdmin cookie:\t{pwn_to_admin()[0]}\n\t\tAdmin profile:\t{pwn_to_admin()[1]}")

if __name__ == '__main__':
	key = randbytes(16)
	main()
