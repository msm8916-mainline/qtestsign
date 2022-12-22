#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2022 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path

from fw import hashseg
from fw.elf import Elf


def _strip_elf(elf: Elf, out: Path):
	print(f"Before: {elf}")
	hashseg.drop(elf)
	elf.update()
	print(f"After: {elf}")

	with open(out, 'wb') as f:
		elf.save(f)


parser = argparse.ArgumentParser(description="""
	Strip ELF file (remove section header table and drop hash segment).
""")
parser.add_argument('elf', type=argparse.FileType('rb'), help="ELF image to strip")
parser.add_argument('-o', '--output', type=Path, help="Output file")
args = parser.parse_args()

with args.elf:
	elf = Elf.parse(args.elf.read())

out = args.output
if not out:
	elf_path = Path(args.elf.name)
	out = elf_path.with_name(elf_path.stem + "-stripped.mbn")

_strip_elf(elf, out)
