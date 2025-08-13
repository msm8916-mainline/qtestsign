#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2021, 2025 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path

from mbn.elf import Elf, Phdr, align

# For definitions of the ELF PHDR flags used by Qualcomm, see:
# https://github.com/coreboot/coreboot/blob/812d0e2f626dfea7e7deb960a8dc08ff0e026bc1/util/qualcomm/mbn_tools.py#L108-L189
PHDR_FLAGS_RELOCATABLE	= 0x8000000


def _determine_region(elf: Elf):
	print(f"ELF: {elf}")

	min_addr = 1 << 64
	max_addr = 0
	partially_relocatable = False
	fully_relocatable = True
	max_align = 0

	for phdr in elf.phdrs:
		if phdr.p_type != Phdr.PT_LOAD or phdr.p_memsz == 0:
			continue
		print(phdr)

		if phdr.p_flags & PHDR_FLAGS_RELOCATABLE:
			partially_relocatable = True
		else:
			fully_relocatable = False

		if phdr.p_paddr < min_addr:
			min_addr = phdr.p_paddr
		end = phdr.p_paddr + phdr.p_memsz
		if end > max_addr:
			max_addr = end

		if phdr.p_align > max_align:
			max_align = phdr.p_align

	size = max_addr - min_addr
	aligned_size = align(size, max_align)

	print()
	print(f"min: {min_addr:#x}, max: {max_addr:#x}, size: {size:#x} (aligned: {aligned_size:#x})")
	print(f"reg = <0x0 {min_addr:#x} 0x0 {aligned_size:#x}>;")
	if partially_relocatable != fully_relocatable:
		print("ELF is only partially relocatable? "
		      f"(partial: {partially_relocatable}, fully: {fully_relocatable})")
	elif fully_relocatable:
		print(f"ELF is relocatable with alignment {max_align:#x}")


parser = argparse.ArgumentParser(description="""
	Show reserved memory region required for ELF.
""")
parser.add_argument('elf', type=argparse.FileType('rb'), help="ELF image to read")
args = parser.parse_args()

with args.elf:
	elf = Elf.parse(args.elf.read())

_determine_region(elf)
