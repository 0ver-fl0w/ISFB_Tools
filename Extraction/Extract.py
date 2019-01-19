# -*- coding: utf-8 -*-
#!/usr/bin/python

import sys, getopt, os
from algorithms import *
from parse import *
import mlib.compression

def decompress(data):
	data = mlib.compression.aplib.decompress(data)
	return data

def main(argv):

	extract = ''
	filename = ''
	try:
		opts, args = getopt.getopt(argv,"he:i:")
	except getopt.GetoptError:
		print "Help: " + sys.argv[0] + " -h"
		print 'Usage: ' + sys.argv[0] + ' -e <payload/config> -i <isfb_binary>'
		return
	for opt, arg in opts:
		if opt == '-h':
			print "ISFB/Gozi/Ursnif Stage 2 Payload/Config Extractor"
			print "Will only work on files containing the 'JJ' Structure after the Section Table\n"
			print 'Usage: ' + sys.argv[0] + ' -e <payload/config> -i <isfb_binary>'
			print "	-e:		Extract Payload/Config"
			print "	-i:		Path to ISFB SECOND STAGE Binary"
			return
		elif opt in ("-e", "--extract"):
			extract = arg
		elif opt in ("-i", "--input"):
			filename = arg
		
	
	if len(filename) <= 0:
		print "Help : " + sys.argv[0] + " -h"
		print 'Usage: ' + sys.argv[0] + ' -e <payload/config> -i <isfb_binary>'
		return

	if extract == "payload":
		
		print "Payload Extraction Mode Selected."
	
		filename_2 = ""
		dos = "This program cannot be run in DOS mode"
		
		struct_1, compress_1, struct_2, compress_2 = Get_Struct_Handler(filename)
	
		if struct_1 == 1:
			return

		print "Located First Structure in Binary"
		if struct_2 != 0:
			print "Located Second Structure in Binary"
			
		if compress_1 == 1:
			print "Decompressing First Section of Data..."
			struct_1 = decompress(struct_1)		# use get struct handler to determine compressed
		

		if dos in struct_1:
			print "Located DOS Message in Decompressed Data."
			f = open("dumped_payload.bin", "wb")
			f.write("\x00\x00\x90\x00" + struct_1[4:])
			f.close()
			print "Performing ROL-XOR ROR-XOR Algorithm on Data..."
			filename = encrypt_main("dumped_payload.bin")
			filename = decrypt_main(filename)
			print "Payload has been Extracted, Fixed, and Saved."	
		
		else:
			print "DOS Message not Located in Decompressed Data. Writing Raw Data to File."
			f = open("dumped_data.bin", "wb")
			f.write(struct_1)
			f.close()
			filename = "dumped_data.bin"
			
		if struct_2 != 0:
		
			if compress_2 == 1:
				print "Decompressing Second Section of Data..."
				struct_2 = decompress(struct_2)
			
			if dos in struct_2:
				print "Located DOS Message in Second Lot of Decompressed Data."
				if os.path.isfile("dumped_payload.bin"):
					f = open("dumped_payload_2.bin", "wb")
					f.write("\x00\x00\x90\x00" + struct_2[4:])
					f.close()
					print "Performing ROL-XOR ROR-XOR Algorithm on Data..."
					filename = encrypt_main("dumped_payload_2.bin")
					filename_2 = decrypt_main(filename)
					print "Payload has been Extracted, Fixed, and Saved."
				else:
					f = open("dumped_payload.bin", "wb")
					f.write("\x00\x00\x90\x00" + struct_2[4:])
					f.close()
					print "Performing ROL-XOR ROR-XOR Algorithm on Data..."
					filename = encrypt_main("dumped_payload.bin")
					filename_2 = decrypt_main(filename)	
					print "Payload has been Extracted, Fixed, and Saved."		
		
			
			else:
				if os.path.isfile("dumped_data.bin"):
					print "DOS Message not Located in Decompressed Data. Writing Raw Data to File."
					f = open("dumped_data_2.bin", "wb")
					f.write(struct_1)
					f.close()
					filename_2 = "dumped_data_2.bin"
					
				else:
					print "DOS Message not Located in Decompressed Data. Writing Raw Data to File."
					f = open("dumped_data.bin", "wb")
					f.write(struct_1)
					f.close()
					filename_2 = "dumped_data.bin"
	
		if struct_2 != 0:
			print "Finished Extracting Payload(s)! Data Output to:", filename, "and", filename_2
		else:
			print "Finished Extracting Payload! Data Output to:", filename
		return 


	elif extract == "config":
	
		file_1 = ""
		file_2 = ""
		print "Config Extraction Mode Selected."
		dos = "This program cannot be run in DOS mode"
		
		struct_1, compress_1, struct_2, compress_2 = Get_Struct_Handler(filename)
	
		if struct_1 == 1:
			return

		if compress_1 == 1:
			print "Decompressing First Section of Data..."
			struct_1 = decompress(struct_1)		
		
		if len(struct_1) > 0xA00:
			if dos in struct_1:
				print "Located DOS Message in Decompressed Data."
				f = open("located_executable.bin", "wb")
				f.write("\x00\x00\x90\x00" + struct_1[4:])
				f.close()
				filename = encrypt_main("located_executable.bin")
				filename = decrypt_main(filename)
				file_1 = "located_executable.bin"
				print "Written Executable to", file_1
		
		else:
			if struct_1 > 140:
				print "Located Possible Configuration in Binary. Attempting to Parse..."
				struct_1 = Parse_Config(struct_1)
				if struct_1 != 1:
					f = open("possible_config.bin", "wb")
					f.write(struct_1)
					f.close()
					file_1 = "possible_config.bin"
				else:
					print "Failed to Parse Possible Configuration. Ignoring."
			else:
				print "Located Unknown Data. Writing Raw Data to File."
				f = open("unknown_data.bin", "wb")
				f.write(struct_1)
				f.close()
				file_1 = "unknown_data.bin"
		
		if len(struct_2) != 0:
			if compress_2 == 1:
				print "Decompressing Second Section of Data..."
				struct_2 = decompress(struct_2)
			if len(struct_2) > 0xA00:
				if dos in struct_2:
					print "Located DOS Message in Decompressed Data."
					if os.path.isfile("located_executable.bin"):
						f = open("located_executable_2.bin", "wb")
						f.write("\x00\x00\x90\x00" + struct_2[4:])
						f.close()
						filename = encrypt_main("located_executable_2.bin")
						filename = decrypt_main(filename)
						file_2 = "located_executable_2.bin"
						print "Written Executable to", file_2
					else:
						f = open("located_executable.bin", "wb")
						f.write("\x00\x00\x90\x00" + struct_2[4:])
						f.close()
						filename = encrypt_main("located_executable.bin")
						filename = decrypt_main(filename)
						file_2 = "located_executable.bin"
						print "Written Executable to", file_2
		
			else:
				if struct_2 > 140:
					print "Located Possible Configuration in Binary. Attempting to Parse..."
					struct_2 = Parse_Config(struct_2)
					if struct_2 != 1:
						if os.path.isfile("possible_config.bin"):
							f = open("possible_config_2.bin", "wb")
							f.write(struct_2)
							f.close()
							file_2 = "possible_config_2.bin"
						else:
							f = open("possible_config.bin", "wb")
							f.write(struct_2)
							f.close()
							file_2 = "possible_config.bin"
					else:
						print "Failed to Parse Possible Configuration. Ignoring."
				else:
					print "Located Unknown Data. Writing Raw Data to File."
					if os.path.isfile("unknown_data.bin"):
						f = open("unknown_data_2.bin", "wb")
						f.write(struct_2)
						f.close()
						file_2 = "unknown_data_2.bin"
					else:
						f = open("unknown_data.bin", "wb")
						f.write(struct_2)
						f.close()
						file_2 = "unknown_data.bin"
	
		if file_1 != "" and file_2 != "":
			print "Extracted Potential Configurations to:", file_1, "and", file_2
		elif file_1 != "" and file_2 == "":
			print "Extracted Potential Configurations to:", file_1
		elif file_1 == "" and file_2 != "":
			print "Extracted Potential Configurations to:", file_2
			
		return 
	


if __name__ == "__main__":
	main(sys.argv[1:])
