#!/usr/bin/env python3

# DEPRECATION

from struct import Struct, error
from binascii import hexlify

# 32bit
ELF32ObjectSectionTableEntrySymbolTable = Struct(b"HLHBBH")
ELF32ObjectSectionTableEntryRelocate = Struct(b"II")
ELF32ObjectSectionTableEntryRelocateAddends = Struct(b"IIi")

# 64bit
ELF64ObjectSectionTableEntrySymbolTable = Struct(b"HBBHQQ")
ELF64ObjectSectionTableEntryRelocate = Struct(b"QQ")
ELF64ObjectSectionTableEntryRelocateAddends = Struct(b"QQl")

ELFObject: dict = {}


def replace_name_in_each_entry():
    entries = ELFObject["section_table"]["entries"]
    strings = entries[ELFObject["section_table"]["string_table_index"]]["values"]
    for entry in entries:
        try:
            if strings[entries[entry]["name"]] != b"":
                entries[entry].update({"name": strings[entries[entry]["name"]]})
        except KeyError:
            pass


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
