from struct import Struct


class SectionTable:

    Offset: int
    EntrySize: int
    Entries: int
    StringTableIndex: int

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

    def __repr__(self) -> str:
        return f"SectionTable<Offset={self.Offset}" \
               f", EntrySize={self.EntrySize}" \
               f", StringTableIndex={self.StringTableIndex}" \
               f", Entries={self.ParsedEntries}>"

    class _Entry:

        ELF32Entry = Struct(b"10I")
        ELF64Entry = Struct(b"2I4Q2I2Q")

        def __init__(self, raw_data: bytes):
            self.raw = raw_data
            self.Parse()
            del self.raw

        def Parse(self):
            if self.raw.__len__() == self.ELF64Entry.size:
                [self.Name,
                 self.Type,
                 self.Flags,
                 self.VirtualAddress,
                 self.SectionOffset, self.SectionSize,
                 self.Link,
                 self.Information,
                 self.AddressAlignment,
                 self.EntrySize] = self.ELF64Entry.unpack(self.raw)
            elif self.raw.__len__() == self.ELF32Entry.size:
                [self.Name,
                 self.Type,
                 self.Flags,
                 self.VirtualAddress,
                 self.SectionOffset, self.SectionSize,
                 self.Link,
                 self.Information,
                 self.AddressAlignment,
                 self.EntrySize] = self.ELF32Entry.unpack(self.raw)

        def __repr__(self) -> str:
            return f"Entry<Name={self.Name}" \
                   f", Type={self.Type}" \
                   f", Flags={self.Flags}" \
                   f", VirtualAddress={self.VirtualAddress}" \
                   f", SectionOffset={self.SectionOffset}" \
                   f", SectionSize={self.SectionSize}" \
                   f", Link={self.Link}" \
                   f", Information={self.Information}" \
                   f", AddressAlignment={self.AddressAlignment}" \
                   f", EntrySize={self.EntrySize}>"
