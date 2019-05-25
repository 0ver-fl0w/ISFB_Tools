import binascii, pefile, mmap
from struct import pack, unpack


rol = lambda val, r_bits, max_bits:	\
    (val << r_bits%max_bits) & (2**max_bits-1) |	\
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
 

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def swap32(i):
    return unpack("<I", pack(">I", i))[0]

def decrypt(encrypt, arg_4):
	decrypt = []
	ror_counter = 0	
	ebx = 0
	
	for i in range(len(encrypt)):
		try:
			encrypt[i] = swap32(encrypt[i])
		except Exception as E:
			print encrypt[i]
			print "Error!. Stopping Decryption."
			print E
			break
		test = encrypt[i] ^ ebx
		ebx = encrypt[i]
		test2 = test ^ arg_4
		ror_counter = ror_counter + 1
		test2 = ror(test2, ror_counter, 32)
		final_data = pack("<I", test2)
		decrypt.append(final_data)

	data = "".join(decrypt)
	n = 2
	arr2 = []
	line = binascii.hexlify(data)
	final = [line[i:i+n] for i in range(0, len(line), n)]
	for i in final:
		arr2.append(int(i, 16))
	print "Decrypted Strings: "
	print arr2
	print data
	
def main():

	filename = raw_input("Enter filename of unpacked ISFB: ")
	executable = open(filename, "rb")
	pe_data = mmap.mmap(executable.fileno(), 0, access=mmap.ACCESS_READ)
	pe = pefile.PE(data=pe_data, fast_load = True)
	for section in pe.sections:
		if ".bss" in section.Name:
			print "Located .BSS section!"
			BSS = section.get_data()
			bss_size = section.VirtualAddress
	BSS = binascii.hexlify(BSS).split("00000000")[0]
	split_bss = [BSS[i:i+8] for i in range(0, len(BSS), 8)]
	encrypted = []
	for i in split_bss:
		if len(i) != 8:
			i = i + "0"
		encrypted.append(int(i, 16))

	date = raw_input("Input campaign date from binary: ")
	date_1 = swap32(int(binascii.hexlify(date[0:4]), 16))
	date_2 = swap32(int(binascii.hexlify(date[4:8]), 16))
	value = date_1 ^ date_2
	value = value + bss_size + 0x0E
	key =  rol(value, 1, 32)
	print "Calculated Key:", hex(key).strip("L")
	decrypt(encrypted, key)
	return
	
if __name__ == "__main__":
	main()
