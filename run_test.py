#!/usr/bin/env python3

import peace

pe = peace.PE("./sample/x86.exe")
# print(pe.__IMAGE_DOS_HEADER__["e_magic"])
pe.show_info()
