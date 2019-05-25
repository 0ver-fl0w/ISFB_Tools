import sys
from Parsing import *
from Algorithms import *


def Handle_Executable(blob):

    global dump_exe
    if "MZ\x90" not in blob[0:4]:
        blob = "MZ\x90\x00" + blob[4:]
    # PE is only added after decompression 
    if blob[0x100:0x102] != "PE":
        blob = blob[:0x100] + "\x50\x45" + blob[0x102:]
    print "Writing to: extracted_exe.bin..."
    with open(dump_exe, "wb") as f:
        f.write(blob)
    print "Written!"
    return

def main(argv):

    global dump_exe
    if len(sys.argv) < 2:
            print "You forgot to input a file!"
            return    
    print "Unpacked ISFB Sample Selected:", sys.argv[1]
    filename = sys.argv[1]
    dump_exe = "extracted_exe.bin"
    executable = False
    raw_data = []
    RSA_Key = ""
    Serpent_Key = ""
    print "Extracting Onboard Configuration..."
    raw_data = get_structures(filename)
    for blob in raw_data:
            # If executable is embedded inside
            if "!This program cannot be" in blob[0:100]:
                    executable = True
                    print "Found Executable! Writing out decompressed executable..."
                    Handle_Executable(blob)
                    continue
            if len(blob) == 0x84:
                print "Located RSA Key inside of Binary. Storing..."
                RSA_Key = blob
            else:
                    print "Located Onboard Configuration! Parsing..."
                    parsed_config, Serpent_Key, C2_urls = parse_config(blob)
                    if parsed_config == 0:
                        continue
                    print "Outputting Parsed Configuration!"
                    for i in parsed_config:
                        print " ", i

    if executable == True:
        print " Checking if dumped binary is in fact ISFB..."
        raw_data_2 = get_structures(dump_exe)
        if raw_data_2 != "":
			for blob in raw_data_2:
				# If executable is embedded inside
				if "!This program cannot be" in blob[0:100]:
						executable = True
						print "Found Executable! Writing out decompressed executable..."
						dump_exe = "extracted_exe_1.bin"
						Handle_Executable(blob)
						continue
				if len(blob) == 0x84:
					print "Located RSA Key inside of Binary. Storing..."
					RSA_Key_1 = blob
				else:
						print "Located Onboard Configuration! Parsing..."
						parsed_config_1, Serpent_Key_1, C2_urls_1 = parse_config(blob)
						print "Outputting Parsed Configuration!"
						for i in parsed_config_1:
							print " ", i
                        print "\nRSA Key: ", binascii.hexlify(RSA_Key_1)
                        print "Serpent Key: ", Serpent_Key_1
                        print "C2 URLs: ", C2_urls_1 
    else:
        print "\nRSA Key: ", binascii.hexlify(RSA_Key)
        print "Serpent Key: ", Serpent_Key
        print "C2 URLs: ", C2_urls                     

if __name__ == "__main__":
    main(sys.argv[1:])
