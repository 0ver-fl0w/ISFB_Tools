# ISFB Analysis Tools

## PyExtract.py
Extracts embedded executable/configuration inside a sample of ISFB. Relies on "JJ" joiner structure being present in binary underneath section table, so if the sample you have does not have the structure, you probably have the first stage. Unpack that and dump the second stage from memory. After using PEBear or a similar tool to unmap the dumped stage, you should be able to use this tool to extract either a third stage payload from inside, or a configuration file - provided that the joiner structure is present.

**Tested with ISFB Version 2.17 - Should work with other Version 2.xx**

Example: python PyExtract.py unpacked_isfb.exe

Requires PEfile

## BSS_Decrypt.py
Decrypts BSS section from unpacked ISFB executable - simply requires the campaign date and will decrypt the section, outputting the raw data after decryption, plus an array of integers for easy importing into IDA Pro for overwriting the BSS section.

Requires PEfile

## Packet_Decryption.py
Pass a C2 response to this and it will Base64 decode the data, RSA decrypt the last block, Serpent decrypt the executable, make sure the MD5 hashes match, and dump out the binary. Make sure that the RSA public key is correct, otherwise it will not decrypt the data correctly.

Example: python Packet_Decryption.py received_data.bin

Requires Crypto
