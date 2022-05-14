from struct import Struct


class SectionTable:

    Offset: int
    EntrySize: int
    Entries: int
    StringTableIndex: int

    ParsedEntries: dict = {}

    def Parse(self, raw_data: bytes):
        for i in range(self.Entries):
            position = self.EntrySize * i
            position_offset = position + self.EntrySize
            _Entry = Entry()
            _Entry.Parse(raw_data[position:position_offset])
            self.ParsedEntries.update({i: _Entry})

    def __repr__(self):
        return f"SectionTable<Offset={self.Offset}" \
               f", EntrySize={self.EntrySize}" \
               f", StringTableIndex={self.StringTableIndex}" \
               f", Entries={self.ParsedEntries}>"


class Entry:

    ELF32Entry = Struct(b"10I")
    ELF64Entry = Struct(b"2I4Q2I2Q")

    def Parse(self, raw_data: bytes):
        if raw_data.__len__() == self.ELF64Entry.size:
            [self.Name,
             self.Type,
             self.Flags,
             self.VirtualAddress,
             self.SectionOffset, self.SectionSize,
             self.Link,
             self.Information,
             self.AddressAlignment,
             self.EntrySize] = self.ELF64Entry.unpack(raw_data)
        elif raw_data.__len__() == self.ELF32Entry.size:
            [self.Name,
             self.Type,
             self.Flags,
             self.VirtualAddress,
             self.SectionOffset, self.SectionSize,
             self.Link,
             self.Information,
             self.AddressAlignment,
             self.EntrySize] = self.ELF32Entry.unpack(raw_data)

    def __repr__(self):
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
