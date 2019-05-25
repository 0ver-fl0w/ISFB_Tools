import pefile, mmap, binascii, struct, itertools
from Algorithms import decompress

class Struct(object):
	
    # Optimized for JJ Structure inside ISFB
	def __init__(self, data):
		self.Magic	= data[0:4]
		self.unk	= data[4:8]
		self.Hash	= data[8:12]
		self.Value	= data[12:16]
		self.Size	= data[16:20]

# Thanks to Maciej Kotowicz: https://journal.cecyf.fr/ojs/index.php/cybin/article/view/15/19
crc_table = {
	"0x556aed8f": "server",
	"0xea9ea760": "bootstrap",
	"0xacf9fc81": "screenshot",
	"0x602c2c26": "keyloglist",
	"0x656b798a": "botnet",
	"0xacc79a02": "knockertimeout",
	"0x955879a6": "sendtimeout",
	"0x31277bd5": "tasktimeout",
	"0x18a632bb": "configfailtimeout",
	"0xd7a003c9": "configtimeout",
	"0x4fa8693e": "key",
	"0xd0665bf6": "domains",
	"0x75e6145c": "domain",
	"0x6de85128": "bctimeout",
	"0xefc574ae": "dga_seed",
	"0xcd850e68": "dga_crc",
	"0x73177345": "dga_base_url",
	"0x11271c7f": "timer",
	"0x584e5925": "timer",
	"0x48295783": "timer",
	"0xdf351e24": "tor32_dll",
	"0x4b214f54": "tor64_dll",
	"0x510f22d2": "tor_domains",
	"0xdf2e7488": "dga_season",
	"0xc61efa7a": "dga_tld",
	"0xec99df2e": "ip_service",
        "0xea1389ef": "dns_servers"
}


def change_endian(i):
	a = i[::-1]
	b = a.encode("hex")
	return b

def parse_struct(structure):
	
	parsed = Struct(structure.replace(" ", ""))
	compressed = parsed.Magic[2:]
	return change_endian(parsed.Value), change_endian(parsed.Size), compressed

# Thanks to Maciej Kotowicz: https://journal.cecyf.fr/ojs/index.php/cybin/article/view/15/19
def parse_config(blob):
    data = blob
    C2_urls = ""
    parsed_config = []
    offset = 8

    count = struct.unpack('Q', data[:8])[0]

    for i in itertools.count(count):
        try:
                name, flags, value, uid = struct.unpack_from("IIQQ", data, offset)
	except Exception as E:
                print "Joined Data is not a configuration. Printing..."
                print blob
                return 0, 0, 0
        if flags & 1:
            value = offset + value
        string_len = len(data[value:].partition("\x00")[0])
        if string_len == 0 and offset > 8:
            break
	 
        if string_len > 0:
            if hex(name).strip("L") in crc_table:
                if crc_table[hex(name).strip("L")] == "key":
                    serpent_key = data[value:value+string_len]
                elif crc_table[hex(name).strip("L")] == "domains":
                    C2_urls = data[value:value+string_len]
                parsed_config.append(crc_table[hex(name).strip("L")] + ": " + data[value:value+string_len])
            else:
                parsed_config.append(hex(name).strip("L") + ": " + data[value:value+string_len])
        offset += 24
		
    return parsed_config, serpent_key, C2_urls

def get_structures(filename):
    structs = []
    raw_data = []
	
    data = open(filename, "rb").read()
    executable = open(filename, "rb")
    pe_data = mmap.mmap(executable.fileno(), 0, access=mmap.ACCESS_READ)
    pe = pefile.PE(data=pe_data, fast_load = True)
    virt_addr = pe.sections[-1].VirtualAddress
    ptr_raw_data = pe.sections[-1].PointerToRawData
	
	# Get addr for JJ
    nt_header = pe.DOS_HEADER.e_lfanew
    file_header = nt_header + 0x04
    optional_header = file_header + 0x12
    size_of_optional_header = pe.FILE_HEADER.SizeOfOptionalHeader
    text = optional_header + size_of_optional_header + 2
    no_sections = pe.FILE_HEADER.NumberOfSections
    size_of_section_headers = 0x20 * (no_sections + 1)
    end_of_sections = text + size_of_section_headers
    start_of_struct = end_of_sections + 0x30
    size_of_structure = 0x28
    structure = data[start_of_struct:start_of_struct+size_of_structure]
	
    first = structure.find("JJ")
	
    if first == -1:
        print "Unable to find JJ Structure in Binary. If this is ISFB, the structure is not supported or it's different."
        return 1
		
	
    struct_1 = structure[first:first+20]
    
    offset_1, size_1, compressed_1 = parse_struct(struct_1)
	
    structs.extend([offset_1, size_1, compressed_1])

    second = structure.find("JJ", first + 1)
	
    if second != -1:
        print "Two structures found in binary."
        struct_2 = structure[second:second+20]
        offset_2, size_2, compressed_2 = parse_struct(struct_2)	
        structs.extend([offset_2, size_2, compressed_2])
	
	
    pointer_to_data = ptr_raw_data - virt_addr + int(structs[0], 16)
    struct_data = data[pointer_to_data:pointer_to_data+int(structs[1], 16)]
    if int(binascii.hexlify(structs[2])) & 0x01:
        print "Appended Data is Compressed."
        raw_data.append(decompress(struct_data))
	
	
    if len(structs) == 6:
        pointer_to_data = ptr_raw_data - virt_addr + int(structs[3], 16)
        struct_data = data[pointer_to_data:pointer_to_data+int(structs[4], 16)]
        if int(binascii.hexlify(structs[5])) & 0x01:
            print "Second Section of Data is also Compressed."
            raw_data.append(decompress(struct_data))
		
    return raw_data
