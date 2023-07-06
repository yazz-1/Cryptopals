from base64 import b64encode


def hex_to_b64(hexStr):
	bytelist = bytes.fromhex(hexStr)
	b64Str = b64encode(bytelist).decode('utf-8')
	return b64Str

def main():
	hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
	result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

	b64_str = hex_to_b64(hex_str)
	decoded = ''.join(chr(byte) for byte in bytes.fromhex(hex_str))

	print("\n---------- Cryptopals: Challenge 1 (Basics) ----------\n")
	print("  We need to convert a hex encoded string to a base64 string:\n")
	print(f"\tHex string:\t\t{hex_str}\n\n\tExpected result:\t{result}\n\tOur base64 string:\t{b64_str}\n\n\tDecoded string:\t\t{decoded}")

if __name__ == '__main__':
	main()
