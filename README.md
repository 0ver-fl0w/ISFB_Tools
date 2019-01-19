# ISFB/Gozi/Ursnif Analysis Tools

## Extract.py
Extracts embedded executable/configuration inside a sample of ISFB. Relies on "JJ" joiner structure being present in binary underneath section table, so if the sample you have does not have the structure, you probably have the first stage. Unpack that and dump the second stage from memory. After using PEBear or a similar tool to unmap the dumped stage, you should be able to use this tool to extract either a third stage payload from inside, or a configuration file - provided that the joiner structure is present.

Example (Extract Payload): python extract.py -e payload -i second_stage.exe                                                     
Example (Extract Config): python extract.py -e config -i third_stage.exe

Requires MLib (https://github.com/mak/mlib) and PEfile
