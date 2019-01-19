# -*- coding: utf-8 -*-
#!/usr/bin/python

import pefile, binascii


class JJ_Struct(object):
	
	def __init__(self, data):
		self.Magic	= data[0:4]
		self.unk	= data[4:8]
		self.Hash	= data[8:12]
		self.Value	= data[12:16]
		self.Size	= data[16:20]
		
class Config(object):
	def __init__(self, config, dns):
		self.C2_URLs	      = config[0]
		if dns == 1:
			self.DNS_IPs = config[1]
			self.Group_ID = config[2]
			self.Server   = config[3]
			self.Key      = config[4]
			self.BC_Out   = config[5]
			self.Timer    = config[6]
			self.DGA_Base = config[8]
			self.DGA_CRC  = config[9]
			self.DGA_TLDs  = config[10]
		else:
			self.Group_ID = config[1]
			self.Server   = config[2]
			self.Key      = config[3]
			self.BC_Out   = config[4]
			self.Timer    = config[5]
			self.DGA_Base = config[7]
			self.DGA_CRC  = config[8]
			self.DGA_TLDs = config[9]
		

def Parse_Config(config):

	pointer = config.find("\x20", 20)
	double_check = config.find("\x20", pointer+1)
	if double_check == -1:
		return 1
	else:
		i = pointer
		#print i
		while True:
			char = config[i]
			if char == "\x00":				# 0x00 is present before URL
				break
			i = i - 1
		#print i
		extracted = config[i + 1:]
	
		#print C2_Urls
		plain_config = extracted
		extracted = extracted.split("\x00")
		if len(extracted) > 12:
			print "Located DNS IP's inside Config."
			parsed_config = Config(extracted, 1)
			C2_URLs  = parsed_config.C2_URLs.split("\x20")
			DNS_IPs  = parsed_config.DNS_IPs.split("\x20")
			DGA_TLDs = parsed_config.DGA_TLDs.split("\x20")
			print "C2 URLs: "
			for C2 in C2_URLs:
				print "	[*]", C2 
			print "DNS IPs: "
			for IP in DNS_IPs:
				print "	[*]", IP 
			print "Group ID: ", parsed_config.Group_ID
			print "Enc. Key: ", parsed_config.Key
			print "DGA Base: ", parsed_config.DGA_Base
			print "DGA CRC : ", parsed_config.DGA_CRC
			print "DGA TLDs: "
			for TLD in DGA_TLDs:
				print "	[*]", TLD
			
		else:
			print "No DNS IP's Located in Config."
			parsed_config = Config(extracted, 0)
			C2_URLs  = parsed_config.C2_URLs.split("\x20")
			DGA_TLDs = parsed_config.DGA_TLDs.split("\x20")
			print "C2 URLs:"
			for C2 in C2_URLs:
				print "	[*]", C2
			print "Group ID:", parsed_config.Group_ID
			print "Enc. Key:", parsed_config.Key
			print "DGA Base:", parsed_config.DGA_Base
			print "DGA CRC :", parsed_config.DGA_CRC
			print "DGA TLDs:"
			for TLD in DGA_TLDs:
				print "	[*]", TLD
			
		return plain_config

def change_endian(i):
	a = i[::-1]
	b = a.encode("hex")
	return b
	

def Get_Raw_Addr(filename):
	
	pe = pefile.PE(filename, fast_load = True)
	Virt_Addr = pe.sections[-1].VirtualAddress
	Ptr_RawData = pe.sections[-1].PointerToRawData
	return Virt_Addr, Ptr_RawData
	
	
def Parse_Struct(struct_1, struct_2):

	parsed_1 = JJ_Struct(struct_1.replace(" ", ""))
	Compressed_1 = parsed_1.Magic[2:]
	if struct_2 != 0x00:
		parsed_2 = JJ_Struct(struct_2.replace(" ", ""))
		Compressed_2 = parsed_2.Magic[2:]
		return change_endian(parsed_1.Value), change_endian(parsed_1.Size), Compressed_1, change_endian(parsed_2.Value), change_endian(parsed_2.Size), Compressed_2
		
	return change_endian(parsed_1.Value), change_endian(parsed_1.Size), Compressed_1, 0x00, 0x00, 0x00

	
def Get_Struct_Handler(filename):

	f = open(filename, "rb")
	data = f.read()
	f.close()
	
	Virt_Addr, Ptr_RawData = Get_Raw_Addr(filename)	
	
	first = data.find("JJ")
	
	if first == -1:
		print "Unable to find JJ Structure in Binary. If this is ISFB, the structure is not supported."
		return 1
		
	second = data.find("JJ", first + 1)
	
	if second > first + 0x40 or second == -1:
		second = 0x00

	struct_1 = data[first:first+0x20]
	
	if second == 0x00:
		struct_2 = 0x00
	else:
		struct_2 = data[second:second+len(struct_1)]
		
	offset_1, size_1, compressed_1, offset_2, size_2, compressed_2 = Parse_Struct(struct_1, struct_2)
	
	location_1 = Ptr_RawData - Virt_Addr + int(offset_1, 16)
	
	struct_data_1 = data[location_1:location_1+int(size_1, 16)]
	
	test = int(binascii.hexlify(compressed_1)) & 0x1
	if test != 0:
		compressed_1 = 1
	else:
		compressed_1 = 0
	
	if offset_2 != 0x00:
  
		test =  int(binascii.hexlify(compressed_2)) & 0x1
		if test != 0:
			compressed_2 = 1
		else:
			compressed_2 = 0
	
		location_2 = Ptr_RawData - Virt_Addr + int(offset_2, 16)
		struct_data_2 = data[location_2:location_2+int(size_2, 16)]
		return struct_data_1, compressed_1, struct_data_2, compressed_2

	return struct_data_1, compressed_1, 0x00, 0x00
