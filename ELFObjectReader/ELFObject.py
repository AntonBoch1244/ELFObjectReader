from typing import BinaryIO

from . import HeaderParser, ProgramTableParser, SectionTableParser


class ELFObject:

    reread_offsets: [int] = []
    Header: HeaderParser.Header
    ProgramTable: ProgramTableParser.ProgramTable
    SectionTable: SectionTableParser.SectionTable

    def __init__(self, file: BinaryIO):
        raw_data = file.read(64)
        self.Header = HeaderParser.Header(raw_data)
        self.ProgramTable = self.Header.ProgramTable
        self.SectionTable = self.Header.SectionTable
        file.seek(self.ProgramTable.Offset, 0)
        raw_data = file.read(self.ProgramTable.EntrySize
                             * self.ProgramTable.Entries)
        self.ProgramTable.Parse(raw_data)
        file.seek(self.SectionTable.Offset, 0)
        raw_data = file.read(self.SectionTable.EntrySize
                             * self.SectionTable.Entries)
        self.SectionTable.Parse(raw_data)

    def __repr__(self) -> str:
        return f"ELFObject<Header={self.Header}" \
               f", ProgramTable={self.ProgramTable}" \
               f", SectionTable={self.SectionTable}>"
