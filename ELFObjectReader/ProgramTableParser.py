from struct import Struct


class ProgramTable:

    Offset: int
    EntrySize: int
    Entries: int

    ParsedEntries: dict = {}

    def Parse(self, raw_data: bytes):
        for i in range(self.Entries):
            position = self.EntrySize * i
            position_offset = position + self.EntrySize
            _Entry = Entry()
            _Entry.Parse(raw_data[position:position_offset])
            self.ParsedEntries.update({i: _Entry})

    def __repr__(self):
        return f"ProgramTable<Offset={self.Offset}" \
               f", EntrySize={self.EntrySize}" \
               f", Entries={self.ParsedEntries}>"


class Entry:

    ELF32Entry: Struct = Struct(b"8I")
    ELF64Entry: Struct = Struct(b"2I6Q")

    Type: int
    Offset: int

    class Address:
        VirtualAddress: int
        PhysicalAddress: int

        def __repr__(self):
            return f"Address<VirtualAddress={self.VirtualAddress}," \
                   f" PhysicalAddress={self.PhysicalAddress}>"

    class SegmentSize:
        InFile: int
        InMemory: int

        def __repr__(self):
            return f"SegmentSize<InFile={self.InFile}," \
                   f" InMemory={self.InMemory}>"

    EntryAddress: Address
    EntrySegmentSize: SegmentSize
    Flags: int
    Align: int

    def SetHumanRecognizableType(self):
        if self.Type == 0:
            self.RecognizableType = "Unused"
        elif self.Type == 1:
            self.RecognizableType = "Loadable"
        elif self.Type == 2:
            self.RecognizableType = "Dynamic Linkable"
        elif self.Type == 3:
            self.RecognizableType = "Interpreter"
        elif self.Type == 4:
            self.RecognizableType = "Note"
        elif self.Type == 5:
            self.RecognizableType = "Shared"
        elif self.Type == 6:
            self.RecognizableType = "Program header"
        elif self.Type == 7:
            self.RecognizableType = "Thread"
        else:
            self.RecognizableType = "Reserved"

    def SetHumanRecognizableFlags(self):
        self.RecognizableFlags = {
            "Executable": self.Flags.__and__(1) == 1,
            "Writable": self.Flags.__and__(2) == 2,
            "Readable": self.Flags.__and__(4) == 4
        }

    def Parse(self, raw_data: bytes):
        if raw_data.__len__() == self.ELF64Entry.size:
            EntryStruct = self.ELF64Entry
        elif raw_data.__len__() == self.ELF32Entry.size:
            EntryStruct = self.ELF32Entry

        self.EntryAddress = self.Address()
        self.EntrySegmentSize = self.SegmentSize()

        if raw_data.__len__() == self.ELF64Entry.size:
            [self.Type,
             self.Flags,
             self.Offset,
             self.EntryAddress.VirtualAddress,
             self.EntryAddress.PhysicalAddress,
             self.EntrySegmentSize.InFile, self.EntrySegmentSize.InMemory,
             self.Align] = EntryStruct.unpack(raw_data)

        elif raw_data.__len__() == self.ELF32Entry.size:
            [self.Type,
             self.Offset,
             self.EntryAddress.VirtualAddress,
             self.EntryAddress.PhysicalAddress,
             self.EntrySegmentSize.InFile, self.EntrySegmentSize.InMemory,
             self.Flags,
             self.Align] = EntryStruct.unpack(raw_data)

        self.SetHumanRecognizableType()
        self.SetHumanRecognizableFlags()

    def __repr__(self) -> str:
        return f"Entry<Type={self.RecognizableType}" \
               f", Flags={self.RecognizableFlags}" \
               f", Offset={self.Offset}" \
               f", Align={self.Align}" \
               f", EntryAddress={self.EntryAddress}" \
               f", EntrySegmentSize={self.EntrySegmentSize}>"
