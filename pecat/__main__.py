#!/usr/bin/env python3
""" pecat, An open-source multi-platform windows Portable Executable(PE) analyzer
"""

import os
import time
import hexdump
import coloredlogs, logging

__author__ = "Andrew Bae"
__contact__ = "dev4ndr3w@gmail.com"

log = logging.getLogger(__name__)

coloredlogs.install(fmt='[%(asctime)s] [%(levelname)s] %(message)s',datefmt="%H:%M:%S")

IMAGE_DOS_SIGNATURE = 0x5A4D # big endian: 0x4D5A

ifb = lambda b: int.from_bytes(b, byteorder="little", signed=False)

class PE:
    __IMAGE_DOS_HEADER__ = {
        "e_magic": 0x00, "e_cblp": 0x00, "e_cp": 0x00, "e_crlc": 0x00,
        "e_cparhdr": 0x00, "e_minalloc": 0x00, "e_maxalloc": 0x00, "e_ss": 0x00,
        "e_sp": 0x00, "e_csum": 0x00, "e_ip": 0x00, "e_cs": 0x00,
        "e_lfarlc": 0x00, "e_ovno": 0x00, "e_res": 0x00, "e_oemid": 0x00,
        "e_oeminfo": 0x00, "e_res2": 0x00, "e_lfanew": 0x00}
    __IMAGE_DOS_HEADER_offset__ = {
        "e_magic": 0x02, "e_cblp": 0x04, "e_cp": 0x06, "e_crlc": 0x08,
        "e_cparhdr": 0x0a, "e_minalloc": 0x0c, "e_maxalloc": 0x0e, "e_ss": 0x10,
        "e_sp": 0x12, "e_csum": 0x14, "e_ip": 0x16, "e_cs": 0x18,
        "e_lfarlc": 0x1a, "e_ovno": 0x1c, "e_res": 0x24, "e_oemid": 0x26,
        "e_oeminfo": 0x28, "e_res2": 0x3c, "e_lfanew": 0x40}
   
    def __init__(self, filename=""):
        self.invalid = 0; self.filename = os.path.abspath(filename) if os.path.exists(filename) else None
        if self.filename == None:
            log.error("Must provide a valid filename") 
        if self.parse() == 0:
            log.info("Parsing PE structure was successful")
        
    def parse(self):
        idh_o = self.__IMAGE_DOS_HEADER_offset__; f = open(self.filename, "rb")

        self.dump = f.read(0x40)
        if ifb(self.dump[0x00:idh_o["e_magic"]]) != IMAGE_DOS_SIGNATURE:
            self.invalid = 1; log.error("Invalid e_magic signature")
            return 1
        prev = 0x00
        for i in idh_o:
            if prev == 0x00:
                self.__IMAGE_DOS_HEADER__["e_magic"] = ifb(self.dump[0x00:idh_o["e_magic"]]);prev = i
                continue
            self.__IMAGE_DOS_HEADER__[i] = ifb(self.dump[idh_o[prev]:idh_o[i]]);prev = i
        return 0
            
    def show_info(self, structure=""):
        if self.invalid == 1:
            log.error("Provided file is not valid")
            return 1
        idh_o = self.__IMAGE_DOS_HEADER_offset__
        log.info("IMAGE_DOS_HEADER")
        for i in idh_o:
            print("{:12} {:#x}".format(i, self.__IMAGE_DOS_HEADER__[i]))
    
