from _02dec import *

def repeating_key_xor(byteLst, keyBytes):
	key = (keyBytes*len(byteLst))[:len(byteLst)]
	xordLst = xor_bytelists(byteLst, key)
	return xordLst

def main():
	txt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	k3y = "ICE"
	resu1t = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	bytelist = txt.encode("utf-8")
	key_bytes = k3y.encode("utf-8")

	result_bytes = repeating_key_xor(bytelist, key_bytes)
	result_hex = ''.join([f'{byte:02x}' for byte in result_bytes])

	print("\n---------- Cryptopals: Challenge 5 (Basics) ----------\n")
	print("  We need to XOR a string against a repeating key:\n")
	print(f"\t\tString:\n\t{txt}\n\n\t\tResult expected:\n{resu1t}\n\n\t\tOur result:\n{result_hex}")

if __name__ == '__main__':
	main()
