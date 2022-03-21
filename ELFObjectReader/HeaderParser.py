import sys
from struct import Struct

from . import ProgramTableParser, SectionTableParser

class Header:


    ELF32: Struct = Struct(b"2HII2II6H")
    ELF64: Struct = Struct(b"2HIL2LI6H")

    class _Identity:

        Identity = Struct(b"16B")
        IsCorrect: bool = False

        # Definitions
        Bitset: int = 0
        Is64: bool = False
        Is32: bool = False
        Endian: bytes = b""
        Version: int = 0
        OS_ABI: str = ""
        ABI_Version: int = 0

        def VerifyIs64Bit(self):
            self.Is64 = self.Bitset == 64

        def VerifyIs32Bit(self):
            self.Is32 = self.Bitset == 32

        def VerifyMagic(self):
            self.IsCorrect = self.raw[0:4] == (0x7f, ord('E'), ord('L'), ord('F'))

        def Parse(self):
            self.VerifyMagic()
            self.Bitset = self.raw[4] * 32
            self.VerifyIs64Bit()
            self.VerifyIs32Bit()
            if not self.Bitset or self.Bitset > 64:
                raise AttributeError("ELFObject contains invalid class.")
            self.Endian = b"<" if self.raw[5] else b">" if self.raw[5] == 2 else False
            if not self.Endian:
                raise AttributeError("ELFObject contains invalid endian of data.")
            self.Version = self.raw[6]

            if self.raw[7] == 0:
                self.OS_ABI = "Unix System V"
            elif self.raw[7] == 3:
                self.OS_ABI = "GNU/Linux"
            else:
                raise AttributeError("Undefined or unsupported OS ABI")

            self.ABI_Version = self.raw[8]

        def __init__(self, raw_data: bytes):
            if raw_data.__len__() != 16:
                raise TypeError("Raw data should contain 16 bytes.")
            self.raw = self.Identity.unpack(raw_data)
            self.Parse()

        def __repr__(self):
            return f"Identity<IsCorrect={self.IsCorrect}," \
                   f" Bitset={self.Bitset}," \
                   f" Endian={'little' if self.Endian == b'<' else 'big'}," \
                   f" Version={self.Version}," \
                   f" OS={self.OS_ABI}," \
                   f" Version_ABI={self.ABI_Version}>"

    def SetHumanRecognizableType(self):
        if self.Type == 0:
            self.RecoglizeableType = "None"
        elif self.Type == 1:
            self.RecoglizeableType = "Relocatable"
        elif self.Type == 2:
            self.RecoglizeableType = "Executable"
        elif self.Type == 3:
            self.RecoglizeableType = "Dynamic"
        elif self.Type == 4:
            self.RecoglizeableType = "Coredump"
        else:
            self.RecoglizeableType = "Unknown type"

        # OS Specific
        pass

        # CPU Specific
        pass

    def SetHumanRecognizableMachine(self):
        if self.Machine == 3:
            self.RecoglizeableMachine = "AMD/Intel x86 architecture"
        elif self.Machine == 62:
            self.RecoglizeableMachine = "AMD/Intel x86-64 architecture"
        else:
            self.RecoglizeableMachine = "Unknown CPU or Architecture"

    def Parse(self):
        if not (self.raw[0] in range(0, 4) or
                self.raw[0] in range(0xfe00, 0xfeff) or  # specific for OS
                self.raw[0] in range(0xff00, 0xffff)):  # specific for CPU
            raise AttributeError("ELF has incorrect type")
        self.Type = self.raw[0]
        self.Machine = self.raw[1]
        self.SetHumanRecognizableType()
        self.SetHumanRecognizableMachine()
        self.ClassVersion = self.raw[2]
        if self.ClassVersion != 1:
            raise AttributeError("ELF has incorrect version")

        self.Entrypoint = self.raw[3]
        self.ProgramTable = ProgramTableParser.ProgramTable()
        self.ProgramTable.Offset = self.raw[4]
        self.ProgramTable.EntrySize = self.raw[8]
        self.ProgramTable.Entries = self.raw[9]
        self.SectionTable = SectionTableParser.SectionTable()
        self.SectionTable.Offset = self.raw[5]
        self.SectionTable.EntrySize = self.raw[10]
        self.SectionTable.Entries = self.raw[11]
        self.SectionTable.StringTableIndex = self.raw[12]
        self.Flags = self.raw[6]
        self.HeaderSize = self.raw[7]
        if self.HeaderSize != 52 or self.HeaderSize != 64:
            raise TypeError(f"ELF has incorrect header size. {self.HeaderSize} != {64 if self.Identity.Is64 else 52 if self.Identity.Is32 else 'How we get here?'}")

    def __init__(self, raw_data: bytes):
        if (raw_data.__len__() != self.ELF32.size + 16) and (raw_data.__len__() != self.ELF64.size + 16):
            raise TypeError(f"Raw data should contain {self.ELF32.size + 16} or {self.ELF64.size + 16}.")
        self.Identity = self._Identity(raw_data[0:16])
        self.ELF32 = Struct(self.Identity.Endian + b"2HII2II6H")
        self.ELF64 = Struct(self.Identity.Endian + b"2HIL2LI6H")
        if sys.version_info.minor == 10:  # Struct(b"<2HIL2LI6H") == Struct(b"2HII2II6H") Why?
            self.ELF64 = Struct(b"2HIL2LI6H")
        if self.Identity.Is64:
            self.raw = self.ELF64.unpack(raw_data[16:])
        if self.Identity.Is32:
            self.raw = self.ELF32.unpack(raw_data[16:])
        self.Parse()

    def __repr__(self):
        return f"Header<Identity={self.Identity}," \
               f" Type={self.RecoglizeableType}," \
               f" Machine={self.RecoglizeableMachine}," \
               f" ClassVersion=Current," \
               f" Entrypoint={self.Entrypoint}," \
               f" ProgramTable=ProgramTable<Offset={self.ProgramTable.Offset}," \
               f" EntrySize={self.ProgramTable.EntrySize}," \
               f" Entries={self.ProgramTable.Entries}>," \
               f" SectionTable=SectionTable<Offset={self.SectionTable.Offset}," \
               f" EntrySize={self.SectionTable.EntrySize}," \
               f" Entries={self.SectionTable.Entries}," \
               f" StringTableIndex={self.SectionTable.StringTableIndex}>," \
               f" Flags={self.Flags}" \
               f" HeaderSize={self.HeaderSize}>"
