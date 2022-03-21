#!/usr/bin/env python3

# DEPRECATION

from struct import Struct, error
from binascii import hexlify

# 32bit
ELF32ObjectSectionTableEntry = Struct(b"10I")
ELF32ObjectSectionTableEntrySymbolTable = Struct(b"HLHBBH")
ELF32ObjectSectionTableEntryRelocate = Struct(b"II")
ELF32ObjectSectionTableEntryRelocateAddends = Struct(b"IIi")
ELF32ObjectProgramTableEntry = Struct(b"8I")

# 64bit
ELF64ObjectSectionTableEntry = Struct(b"2I4L2I2L")
ELF64ObjectSectionTableEntrySymbolTable = Struct(b"HBBHLL")
ELF64ObjectSectionTableEntryRelocate = Struct(b"LL")
ELF64ObjectSectionTableEntryRelocateAddends = Struct(b"LLl")
ELF64ObjectProgramTableEntry = Struct(b"2I6L")

ELFObject: dict = {}


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


def read_program_table(entry):
    # TODO: REIMPLEMENT CAUSE INCORRECT RESULTS
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
        except error:
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
                i: {"address": hex(address),
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
                    i: {"address": hex(address),
                        "info": {
                            "sym": info >> 32,
                            "type": info & 0xffffffff
                        }}
                })
                i += 1
        except error:
            pass  # TODO: Handle!

        entry.update({"values": Relocate})
