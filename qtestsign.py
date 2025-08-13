#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2021-2022 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path

from fw import hashseg
from fw.elf import Elf

# Taken from the certificates (DER format) in official firmwares
FW_SW_ID = {
	"sbl1": 0x00,
	"mba": 0x01,
	"modem": 0x02,
	"prog": 0x03,
	"adsp": 0x04,
	"devcfg": 0x05,
	"tz": 0x07,
	"aboot": 0x09,
	"uefi": 0x09,
	"rpm": 0x0A,
	"tz-app": 0x0C,
	"wcnss": 0x0D,
	"venus": 0x0E,
	"wlanmdsp": 0x12,
	"gpu": 0x14,
	"hyp": 0x15,
	"cdsp": 0x17,
	"slpi": 0x18,
	"abl": 0x1C,
	"ipa": 0x1D,
	"cmnlib": 0x1F,
	"shrm": 0x20,
	"aop": 0x21,
	"multi-image": 0x22,
	"multi-image-qti": 0x23,
	"qup": 0x24,
	"xbl-config": 0x25,
	"cpucp": 0x31,
	"aop-devcfg": 0x3D,
	"xbl-ramdump": 0x42,
	"cdsp1": 0x44,
	"modem-dtb": 0x51,
	"cdsp-dtb": 0x52,
	"adsp-dtb": 0x53,
	"gpdsp0": 0x58,
	"gpdsp1": 0x5A,
	"av1": 0x69,
	"kernel": 0x71,
}


def _sign_elf(b: bytes, out: Path, version: int, sw_id: int):
	elf = Elf.parse(b)

	print(f"Before: {elf}")
	hashseg.generate(elf, version, sw_id)
	print(f"After: {elf}")

	with open(out, 'wb') as f:
		elf.save(f)


parser = argparse.ArgumentParser(description="""
	"Sign" Qualcomm firmware using a dummy certificate chain.

	NOTE: The image format is only partially implemented. There is actually
	no signature generated! This works only for devices that have firmware
	secure boot disabled. Most Qualcomm devices available in production have
	firmware secure boot permanently enabled (with no way to disable it).
	They will fail to boot when flashing modified firmware!
""")
parser.add_argument('type', choices=FW_SW_ID.keys(), help="Firmware type (for SW_ID)")
parser.add_argument('elf', type=argparse.FileType('rb'), help="ELF image to sign")
parser.add_argument('-v', '--version', type=int, choices=[3, 5, 6, 7], default=3,
					help="MBN header version. Must be set correctly depending on the target chipset. "
						 "See README for details.")
parser.add_argument('-o', '--output', type=Path, help="Output file")
args = parser.parse_args()

with args.elf:
	elf_bytes = args.elf.read()

out = args.output
if not out:
	elf_path = Path(args.elf.name)
	out = elf_path.with_name(elf_path.stem + "-test-signed.mbn")

_sign_elf(elf_bytes, out, args.version, FW_SW_ID[args.type])
