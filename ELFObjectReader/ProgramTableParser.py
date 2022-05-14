from struct import Struct


class ProgramTable:

    Offset: int
    EntrySize: int
    Entries: int

    ParsedEntries: dict = {}

    def __init__(self, raw_data: bytes):
        self.raw = raw_data
        self.Parse()
        del self.raw

    def Parse(self):
        for i in range(self.Entries):
            position = self.EntrySize * i
            position_offset = position + self.EntrySize
            Entry = self._Entry(self.raw[position:position_offset])
            self.ParsedEntries.update({i: Entry})

    def __repr__(self):
        return f"ProgramTable<Offset={self.Offset}" \
               f", EntrySize={self.EntrySize}" \
               f", Entries={self.ParsedEntries}>"

    class _Entry:

        ELF32Entry: Struct = Struct(b"8I")
        ELF64Entry: Struct = Struct(b"2I6Q")

        Type: int
        Offset: int

        class _Address:
            VirtualAddress: int
            PhysicalAddress: int

            def __repr__(self) -> str:
                return f"Address<VirtualAddress={self.VirtualAddress}," \
                       f" PhysicalAddress={self.PhysicalAddress}>"

        class _SegmentSize:
            InFile: int
            InMemory: int

            def __repr__(self) -> str:
                return f"SegmentSize<InFile={self.InFile}" \
                       f", InMemory={self.InMemory}>"

        Address: _Address
        SegmentSize: _SegmentSize
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

        def Parse(self):
            self.Address = self._Address()
            self.SegmentSize = self._SegmentSize()

            if self.raw.__len__() == self.ELF64Entry.size:
                [self.Type,
                 self.Flags,
                 self.Offset,
                 self.Address.VirtualAddress,
                 self.Address.PhysicalAddress,
                 self.SegmentSize.InFile, self.SegmentSize.InMemory,
                 self.Align] = self.ELF64Entry.unpack(self.raw)
            elif self.raw.__len__() == self.ELF32Entry.size:
                [self.Type,
                 self.Offset,
                 self.Address.VirtualAddress,
                 self.Address.PhysicalAddress,
                 self.SegmentSize.InFile, self.SegmentSize.InMemory,
                 self.Flags,
                 self.Align] = self.ELF32Entry.unpack(self.raw)

            self.SetHumanRecognizableType()
            self.SetHumanRecognizableFlags()

        def __init__(self, raw_data: bytes):
            self.raw = raw_data
            self.Parse()
            del self.raw

        def __repr__(self) -> str:
            return f"Entry<Type={self.RecognizableType}" \
                   f", Flags={self.RecognizableFlags}" \
                   f", Offset={self.Offset}" \
                   f", Align={self.Align}" \
                   f", Address={self.Address}" \
                   f", SegmentSize={self.SegmentSize}>"
