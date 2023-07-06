

def xor_bytelists(byteLst1, byteLst2):
	return [byte1 ^byte2 for byte1, byte2 in zip(byteLst1, byteLst2)]

def main():
	hex_str1 = '1c0111001f010100061a024b53535009181c'
	hex_str2 = '686974207468652062756c6c277320657965'
	result = '746865206b696420646f6e277420706c6179'

	bytelist1 = bytes.fromhex(hex_str1)
	bytelist2 = bytes.fromhex(hex_str2)
	xord_bytes = xor_bytelists(bytelist1, bytelist2)
	xord_hex = ''.join([f'{byte:2x}' for byte in xord_bytes])
	decoded = ''.join(chr(byte) for byte in xord_bytes)

	print("\n---------- Cryptopals: Challenge 2 (Basics) ----------\n")
	print("  We need to XOR two hex encoded strings:\n")
	print(f"\t\tOur result hex string:\t{xord_hex}\n\t\tResult expected:\t\t{result}\n\n\t\tDecoded string:\t\t{decoded}")

if __name__ == '__main__':
	main()
