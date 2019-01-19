# -*- coding: utf-8 -*-
#!/usr/bin/python

import binascii, os
from struct import pack, unpack


def fix(name):

	o_machine	= 0
	e_lfanew	= ""
	
	f = open(name, "rb")
	data = f.read()
	f.close()
	os.remove(name)
	
	e_lfanew = data[60:60+4]
	size_1 = len(data[2:60])
	nulls_1 = "\x00" * size_1
	o_machine = unpack("<L", e_lfanew)[0] + 4
	size_2 = o_machine - len("MZ" + nulls_1 + e_lfanew) - 4
	nulls_2 = "\x00" * size_2
	fixed = "MZ" + nulls_1 + e_lfanew + nulls_2 + "PE" + ("\x00" * 2) + data[o_machine:]
	
	f = open(name, "wb")
	f.write(fixed)
	f.close()
	return name
	

def unpack_i(i):
    return unpack("<I", pack(">I", i))[0]


rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


def rol_xor(data):
	global rol_counter, rol_xor_val, rol_xor_byte, encrypted_data
	
	rol_counter = rol_counter + 1
	byte = data				
	counter_val = rol_counter
	byte = rol(byte, counter_val, 32)
	byte = byte ^ rol_xor_val
	byte = byte ^ rol_xor_byte
	rol_xor_val = byte
	encrypted_data.append(hex(unpack_i(rol_xor_val)))
	
	
def encrypt_main(name):
	global rol_counter, rol_xor_val, rol_xor_byte, encrypted_data
	rol_counter = 0
	rol_xor_val = 0
	rol_xor_byte = 0
	encrypted_data = []

	f = open(name, "rb")
	data = f.read()
	f.close()
	os.remove(name)
	data = data.encode("hex")
	
	for i in range(0,len(data),8):
		bytes = data[i:i+8]				# Get DWORDs
		bytes = int(bytes, 16)
		bytes = binascii.hexlify(pack('<I', bytes))
		rol_xor(int(bytes, 16))
	
	
	string = ""
	for i in encrypted_data:
		i = int(i, 16)
		i = hex(unpack_i(i))
		i = int(i, 16)
		i = binascii.hexlify(pack('<I', i))
		string += i
	encrypted_payload = []
	encrypted_payload = [string[i:i+2] for i in range(0, len(string), 2)]
	f = open("encrypted_binary.bin", "wb")
	for i in encrypted_payload:
		f.write(binascii.unhexlify(i))
	f.close()
		
	return "encrypted_binary.bin"

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def ror_xor(data):

	global ror_xor_val, ror_xor_byte, ror_counter, ror_byte, decrypted_data
	
	byte = data
	add = byte
	byte = byte ^ ror_xor_val
	byte = byte ^ ror_xor_byte
	ror_counter = ror_counter + 1
	ror_xor_val = add
	ror_byte = ror_counter
	add = add + ror_byte
	byte = ror(byte, ror_byte, 32)
	decrypted_data.append(hex(unpack_i(byte)))
	
	
def decrypt_main(name):

	global ror_xor_byte, ror_xor_val, ror_counter, ror_byte, decrypted_data
	ror_xor_byte = 0
	ror_xor_val = 0
	ror_counter = 0
	ror_byte = 0
	decrypted_data = []
	i = 0
	f = open(name, "rb")
	data = f.read()
	f.close()
	os.remove(name)
	data = data.encode("hex")
	for i in range(0,len(data),8):
		bytes = data[i:i+8]				# Get DWORD
		bytes = int(bytes, 16)
		bytes = binascii.hexlify(pack('<I', bytes))
		ror_xor(int(bytes, 16))
		
	string = ""
	for i in decrypted_data:
	
		i = int(i, 16)
		i = hex(unpack_i(i))
		i = int(i, 16)
		i = binascii.hexlify(pack('<I', i))
		string += i
		
	decrypted_payload = []
	decrypted_payload = [string[i:i+2] for i in range(0, len(string), 2)]
	decrypted_payload[0] = '4D'
	decrypted_payload[1] = '5A'
	f = open("dumped_executable.bin", "wb")
	for i in decrypted_payload:
		f.write(binascii.unhexlify(i))
	f.close()
	fixed = fix("dumped_executable.bin")
	return fixed
