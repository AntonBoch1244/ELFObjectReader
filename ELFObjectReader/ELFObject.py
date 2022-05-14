from typing import BinaryIO

from . import HeaderParser, ProgramTableParser, SectionTableParser


class ELFObject:

    reread_offsets: [int] = []
    Header: HeaderParser.Header
    ProgramTable: ProgramTableParser.ProgramTable
    SectionTable: SectionTableParser.SectionTable

    def __init__(self, file: BinaryIO):
        self.Header = HeaderParser.Header(file.read(64))
        self.ProgramTable = self.Header.ProgramTable
        self.SectionTable = self.Header.SectionTable

    def __repr__(self) -> str:
        return f"ELFObject<Header={self.Header}" \
               f", ProgramTable={self.ProgramTable}" \
               f", SectionTable={self.SectionTable}>"
