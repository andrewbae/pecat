#!/usr/bin/env python3
""" PEace, An open-source multi-platform windows Portable Executable(PE) analyzer

    pe = peload(filename="./pe.exe") # pe: pe information object
    print(pe.)
"""

import os
import hashlib
import hexdump

__author__ = "Andrew Peterson"
__contact__ = "dev4ndr3w@gmail.com"

IMAGE_DOS_SIGNATURE = 0x4D5A

class PE:
    __IMAGE_DOS_HEADER_offset__ = {
        "e_magic": 0x02, "e_cblp": 0x04, "e_cp": 0x06, "e_crlc": 0x08,
        "e_cparhdr": 0x0a, "e_minalloc": 0x0c, "e_maxalloc": 0x0e, "e_ss": 0x10,
        "e_sp": 0x12, "e_csum": 0x14, "e_ip": 0x16, "e_cs": 0x18,
        "e_lfarlc": 0x1a, "e_ovno": 0x1c, "e_res": 0x24, "e_oemid": 0x26,
        "e_oeminfo": 0x28, "e_res2": 0x3c, "e_lfanew": 0x40}
    def __init__(self, filename=""):
        self.filename = os.path.abspath(filename) if os.path.exists(filename) else None
        if self.filename is None:
            raise ValueError("Must provide a valid filename")
        self.parse()

    def parse(self):
        f = open(self.filename, "rb")
        # parse IMAGE_DOS_HEADER structure
        self.IMAGE_DOS_HEADER = f.read(0x40)

        idh_o = self.__IMAGE_DOS_HEADER_offset__
        e_lfanew = self.IMAGE_DOS_HEADER[idh_o["e_res2"]:idh_o["e_lfanew"]]
        print(int.from_bytes(e_lfanew, byteorder="little", signed=True))

#        idh_o["e_magic"] = IMAGE_DOS_HEADER[0:2]

        print(hexdump.hexdump(self.IMAGE_DOS_HEADER))
    def show_info(self, structure=""):
        idh_o = self.__IMAGE_DOS_HEADER_offset__
        if structure is "IMAGE_DOS_HEADER" or structure is "":
            prev = 0x00
            for i in idh_o:
                if prev is 0x00:
                    dump = self.IMAGE_DOS_HEADER[0x00:idh_o[i]]
                    dump = int.from_bytes(dump, byteorder="little", signed=True)
                    print("name: {} {}".format(i, hex(dump)))
                    prev = i
                    continue
                dump = self.IMAGE_DOS_HEADER[idh_o[prev]:idh_o[i]]
                dump = int.from_bytes(dump, byteorder="little", signed=False)
                print("name: {} {}".format(i, hex(dump)))
                prev = i
                print(i)
                print(idh_o[i])

class dump:
    pass


def info(self):
    """
    Features:
        1. show full path of file
        2. show architecture
        3. show pe is valid
    """
    basic_info = {
        "file": self.filename,
        "arch": "s",
        "valid": "d"
    }
    return basic_info

def parse_pe():
    pass
