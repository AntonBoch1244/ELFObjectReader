#!/usr/bin/env python3

from . import HeaderParser
from sys import argv


ELF_File = open(argv[1], 'rb')
print(HeaderParser.Header(ELF_File.read(64)))
assert False
# parse_Program_table()
parse_Section_table()
read_section_table(ELFObject["section_table"]["entries"][ELFObject["section_table"]["string_table_index"]])
replace_name_in_each_entry()
for ste in ELFObject["section_table"]["entries"]:
    read_section_table(ELFObject["section_table"]["entries"][ste])
pprint(ELFObject)
