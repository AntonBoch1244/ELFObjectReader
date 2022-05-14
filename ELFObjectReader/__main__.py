#!/usr/bin/env python3

from . import ELFObject
from sys import argv

for arg in argv[1:]:
    print(f"Reading {arg}...")
    ELF_File = open(arg, 'rb')
    print(ELFObject.ELFObject(ELF_File))
