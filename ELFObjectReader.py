#!/usr/bin/env python3

from struct import Struct as raw_structure, error as struct_error
from pprint import pprint
from binascii import hexlify
import sys

# 32bit
ELF32ObjectHeader = raw_structure(b"16B2HII2II6H")
ELF32ObjectSectionTableEntry = raw_structure(b"10I")
ELF32ObjectSectionTableEntrySymbolTable = raw_structure(b"HLHBBH")
ELF32ObjectSectionTableEntryRelocate = raw_structure(b"II")
ELF32ObjectSectionTableEntryRelocateAddends = raw_structure(b"IIi")
ELF32ObjectProgramTableEntry = raw_structure(b"8I")

# 64bit
ELF64ObjectHeader = raw_structure(b"16B2HIL2LI6H")
ELF64ObjectSectionTableEntry = raw_structure(b"2I4L2I2L")
ELF64ObjectSectionTableEntrySymbolTable = raw_structure(b"HBBHLL")
ELF64ObjectSectionTableEntryRelocate = raw_structure(b"LL")
ELF64ObjectSectionTableEntryRelocateAddends = raw_structure(b"LLl")
ELF64ObjectProgramTableEntry = raw_structure(b"2I6L")

ELFObject: dict = {}


def ELFObject_reparse(Object, Structure):
    Object["File"].seek(0, 0)
    try:
        Object.update({"Structure": Structure, "Object": Structure.unpack(Object["File"].read(Structure.size))})
    except struct_error:
        print("Can't read this file cause header size is incorrect.")
        exit(1)
    global ELFObject
    ELFObject = Object


def parse_ELF_identity():
    verify_with = (0x7f, ord('E'), ord('L'), ord('F'))
    if ELFObject["Object"][0:4] == verify_with:
        print("magic ok, it is actual ELF Object")
        ELFObject.update({"ei_magic": True})
    if ELFObject["Object"][4] == 0:
        print("invalid class")
        exit(1)
    elif ELFObject["Object"][4] == 1:
        print("32bit Object, reparsing")
        ELFObject.update({"ei_bitness": 32})
        ELFObject_reparse(ELFObject, ELF32ObjectHeader)
    elif ELFObject["Object"][4] == 2:
        print("64bit Object, reparsing")
        ELFObject.update({"ei_bitness": 64})
        ELFObject_reparse(ELFObject, ELF64ObjectHeader)
    else:
        print("invalid class")
        exit(1)

    if ELFObject["Object"][5] == 0:
        print("invalid data")
        exit(1)
    elif ELFObject["Object"][5] == 1:
        ELFObject.update({"ei_data_representation": "little"})
    elif ELFObject["Object"][5] == 2:
        print("class are big endian, reparsing")
        ELFObject.update({"ei_data_representation": "big"})
    else:
        print("invalid data")
        exit(1)

    ELFObject.update({"ei_version": ELFObject["Object"][6]})

    if ELFObject["Object"][7] == 0:
        ELFObject.update({"ei_os": "Unix System V"})
    elif ELFObject["Object"][7] == 3:
        ELFObject.update({"ei_os": "GNU/Linux"})
    else:
        print("unusable object")
        exit(2)

    ELFObject.update({"ei_abi": ELFObject["Object"][8]})


def parse_ELF_locations():
    ELFObject.update({
        "entrypoint": ELFObject["Object"][19],
        "program_table": {
            "offset": ELFObject["Object"][20],
            "entry_size": ELFObject["Object"][24],
            "entries": ELFObject["Object"][25]
        },
        "section_table": {
            "offset": ELFObject["Object"][21],
            "entry_size": ELFObject["Object"][26],
            "entries": ELFObject["Object"][27],
            "string_table_index": ELFObject["Object"][28]
        },
        "flags": ELFObject["Object"][22],
        "header_size": ELFObject["Object"][23]
    })


def parse_ELF_header():
    parse_ELF_identity()

    if ELFObject["Object"][16] == 0:
        print("ELF type is none")
        exit(1)
    elif ELFObject["Object"][16] == 1:
        ELFObject.update({"eh_type": "relocateable"})
    elif ELFObject["Object"][16] == 2:
        ELFObject.update({"eh_type": "executable"})
    elif ELFObject["Object"][16] == 3:
        ELFObject.update({"eh_type": "shared"})
    elif ELFObject["Object"][16] == 4:
        ELFObject.update({"eh_type": "coredump"})
    else:
        print("ELF type invalid")
        exit(1)

    if ELFObject["Object"][17] == 3:
        ELFObject.update({"eh_machine": "IA-32"})
    elif ELFObject["Object"][17] == 62:
        ELFObject.update({"eh_machine": "IA-32E/AMD64"})  # longmode extension appears in AMD64
    else:
        print("Executable environment unsupported by this parser")
        exit(3)

    if ELFObject["Object"][18] == 0:
        print("invalid version")
        exit(1)
    elif ELFObject["Object"][18] == 1:
        ELFObject.update({"eh_version": "current"})
    else:
        print("invalid version")
        exit(1)

    parse_ELF_locations()


def parse_Program_table():
    ELFObject["File"].seek(ELFObject["program_table"]["offset"], 0)
    count = ELFObject["program_table"]["entries"]
    ELFObject["program_table"].update({"entries": {}})
    if ELFObject["ei_bitness"] == 64:
        PTE = ELF64ObjectProgramTableEntry
    elif ELFObject["ei_bitness"] == 32:
        PTE = ELF32ObjectProgramTableEntry
    else:
        print("PTE cannot processed")
        exit(1)
    for i in range(count):
        OBJECT = PTE.unpack(ELFObject["File"].read(PTE.size))
        ELFObject["program_table"]["entries"].update({i: {
            "type": OBJECT[0],
            "offset": OBJECT[1],
            "address": {
                "virtual": OBJECT[2],
                "physical": OBJECT[3]
            },
            "segment_size": {
                "file": OBJECT[4],
                "memory": OBJECT[5]
            },
            "flags": OBJECT[6],
            "align": OBJECT[7]
        }})
    del i, count, OBJECT


def parse_Section_table():
    # TODO: check for parse_ELF_Locations
    ELFObject["File"].seek(ELFObject["section_table"]["offset"], 0)
    count = ELFObject["section_table"]["entries"]
    ELFObject["section_table"].update({"entries": {}})
    if ELFObject["ei_bitness"] == 64:
        STE = ELF64ObjectSectionTableEntry
    elif ELFObject["ei_bitness"] == 32:
        STE = ELF32ObjectSectionTableEntry
    else:
        print("STE cannot processed")
        exit(1)
    for i in range(count):
        OBJECT = STE.unpack(ELFObject["File"].read(STE.size))
        ELFObject["section_table"]["entries"].update({i: {
            "name": OBJECT[0],
            "type": OBJECT[1],
            "flags": OBJECT[2],
            "virtual_address": OBJECT[3],
            "section_offset": OBJECT[4],
            "section_size": OBJECT[5],
            "link": OBJECT[6],
            "information": OBJECT[7],
            "address_alignment": OBJECT[8],
            "entry_size": OBJECT[9]
        }})
    del i, count, OBJECT


def replace_name_in_each_entry():
    entries = ELFObject["section_table"]["entries"]
    strings = entries[ELFObject["section_table"]["string_table_index"]]["values"]
    for entry in entries:
        try:
            if strings[entries[entry]["name"]] != b"":
                entries[entry].update({"name": strings[entries[entry]["name"]]})
        except KeyError:
            pass

# TODO: REIMPLEMENT CAUSE INCORRECT RESULTS
def read_program_table(entry):
    file = ELFObject["File"]
    alignment = entry["align"]
    good_size = entry["segment_size"]["file"] + (entry["segment_size"]["file"] % alignment)
    file.seek(entry["address"]["physical"], 0)
    data = file.read(good_size)
    print(hexlify(data))


def read_section_table(entry, typeOf):
    file = ELFObject["File"]
    alignment = entry["address_alignment"]
    good_size = entry["section_size"] + (entry["section_size"] % alignment)
    file.seek(entry["section_offset"], 0)
    OBJECT = file.read(good_size)
    if typeOf == 0:
        entry.update({"values": None})
    elif typeOf == 2:  # SymbolTable
        SymbolTable: dict = {}

        entry.update({"values": SymbolTable})
    elif typeOf == 3:  # StringTable
        StringTable: dict = {}
        i: int = 0
        temp_bytestring = b""
        for char in OBJECT:
            if char == 0:
                StringTable.update({i: temp_bytestring})
                i += 1
                temp_bytestring = b""
            else:
                temp_bytestring += bytes(chr(char), "ascii")
        entry.update({"values": StringTable})
    pass


def read_program_table(entry):
    # TODO: REIMPLEMENT CAUSE INCORRECT RESULTS
    file = ELFObject["File"]
    alignment = entry["align"]
    good_size = entry["segment_size"]["file"] + (entry["segment_size"]["file"] % alignment)
    file.seek(entry["address"]["physical"], 0)
    data = file.read(good_size)
    print(hexlify(data))


def read_section_table(entry):
    file = ELFObject["File"]
    alignment = entry["address_alignment"]
    try:
        good_size = entry["section_size"] + (entry["section_size"] % alignment)
    except ZeroDivisionError:
        good_size = 0
    file.seek(entry["section_offset"], 0)

    OBJECT = file.read(good_size)

    if entry["type"] == 0:
        entry.update({"values": None})
    elif entry["type"] == 2:  # SymbolTable
        SymbolTable: dict = {}
        try:
            i: int = 0
            for offset in range(0, entry["section_size"] - 1, 24):
                name, info, other, section_index, value, size = ELF64ObjectSectionTableEntrySymbolTable.unpack(OBJECT[offset:offset + 24])
                SymbolTable.update({
                    i: {
                        "name": name,
                        "info": info,
                        "other": other,
                        "section_index": section_index,
                        "value": value,
                        "size": size
                    }
                })
                i += 1
        except struct_error:
            pass  # TODO: Handle!
        entry.update({"values": SymbolTable})
    elif entry["type"] == 3:  # StringTable
        StringTable: dict = {}
        i: int = 0
        temp_bytestring = b""
        for char in OBJECT:
            if char == 0:
                StringTable.update({i: temp_bytestring})
                i += 1
                temp_bytestring = b""
            else:
                temp_bytestring += bytes(chr(char), "ascii")
        entry.update({"values": StringTable})
    elif entry["type"] == 4:
        RelocateAddend: dict = {}
        i: int = 0
        for offset in range(0, entry["section_size"]-1, entry["entry_size"]):
            OBJECTS = ELF64ObjectSectionTableEntryRelocateAddends.unpack(OBJECT[offset:offset+entry["entry_size"]])
            address, info, addend = OBJECTS
            RelocateAddend.update({
                i: {"address": address,
                    "info": {
                        "sym": info >> 32,
                        "type": info & 0xffffffff
                    },
                    "addend": addend}
            })
            i += 1
        entry.update({"values": RelocateAddend})
    elif entry["type"] == 7:
        Relocate: dict = {}
        try:
            i: int = 0
            for offset in range(0, entry["section_size"]-1, 16):
                OBJECTS = ELF64ObjectSectionTableEntryRelocate.unpack(OBJECT[offset:offset+16])
                address, info = OBJECTS
                Relocate.update({
                    i: {"address": address,
                        "info": {
                            "sym": info >> 32,
                            "type": info & 0xffffffff
                        }}
                })
                i += 1
        except struct_error:
            pass  # TODO: Handle!

        entry.update({"values": Relocate})


if __name__ == '__main__':
    ELFObject.update({"File": open(sys.argv[1], 'rb')})
    if sys.argv.__contains__("--arch=x64"):
        ELFObject_reparse(ELFObject, ELF64ObjectHeader)
    else:
        ELFObject_reparse(ELFObject, ELF32ObjectHeader)
    parse_ELF_header()
    # parse_Program_table()
    parse_Section_table()
    read_section_table(ELFObject["section_table"]["entries"][ELFObject["section_table"]["string_table_index"]])
    replace_name_in_each_entry()
    for ste in ELFObject["section_table"]["entries"]:
        read_section_table(ELFObject["section_table"]["entries"][ste])
    pprint(ELFObject)
