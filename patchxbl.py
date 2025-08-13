#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path

from mbn import hashseg
from mbn.elf import Elf


XBL_CORE_ADDR_OFFSET = 0xfc00000
XBL_CORE_ADDR_MASK = 0xfffffff


def _patch_xbl_elf(elf: Elf, out: Path, args):
	print(f"Before: {elf}")
	hashseg.drop(elf)

	if args.core:
		# Find xbl_core segment using heuristic
		core_phdr = next(phdr for phdr in elf.phdrs
						 if (phdr.p_paddr & XBL_CORE_ADDR_MASK) == XBL_CORE_ADDR_OFFSET)
		print(f"Found xbl_core phdr: {core_phdr}")

		# Replace with new data
		with args.core:
			core_phdr.data = args.core.read()
			core_phdr.p_filesz = len(core_phdr.data)
			core_phdr.p_memsz = len(core_phdr.data)

	elf.update()
	print(f"After: {elf}")

	with open(out, 'wb') as f:
		elf.save(f)


parser = argparse.ArgumentParser(description="""
	Replace sections in Qualcomm XBL image.
""")
parser.add_argument('elf', type=argparse.FileType('rb'), help="XBL ELF image to patch")
parser.add_argument('-o', '--output', type=Path, help="Output file")
parser.add_argument('-c', '--core', type=argparse.FileType('rb'),
					help="Flat binary (not ELF) to patch into xbl_core segment")
args = parser.parse_args()

with args.elf:
	elf = Elf.parse(args.elf.read())

out = args.output
if not out:
	elf_path = Path(args.elf.name)
	out = elf_path.with_name(elf_path.stem + "-patched.elf")

_patch_xbl_elf(elf, out, args)
