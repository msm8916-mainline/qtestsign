#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2022 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List

from mbn.elf import Elf


def _merge_elfs(elfs: List[Elf], out: Path):
	print(f"Input:{elfs}")

	main = elfs[0]
	for elf in elfs[1:]:
		main.phdrs += elf.phdrs
	main.update()
	print(f"Merged: {main}")

	with open(out, 'wb') as f:
		main.save(f)


parser = argparse.ArgumentParser(description="""
	Merge program headers and segments from multiple ELF files into a single ELF image.
	The ELF header is taken from the first ELF image, then program headers
	and segments are appended from all others.
""")
parser.add_argument('elf', type=argparse.FileType('rb'), help="ELF images", nargs='+')
parser.add_argument('-o', '--output', type=Path, help="Output file", required=True)
args = parser.parse_args()

elfs = []
for elf in args.elf:
	with elf:
		elfs.append(Elf.parse(elf.read()))

_merge_elfs(elfs, args.output)
