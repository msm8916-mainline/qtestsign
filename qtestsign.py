#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2021-2022 Stephan Gerhold
from __future__ import annotations

import argparse
from pathlib import Path

import hashseg
from elf import Elf

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
	"cmnlib": 0x1F,
	"aop": 0x21,
	"qup": 0x24,
	"xbl-config": 0x25,
}


def _sign_elf(b: bytes, out: Path, version: int, sw_id: int):
	elf = Elf.parse(b)

	print(f"Before: {elf}")
	hashseg.generate(elf, version, sw_id)
	print(f"After: {elf}")

	with open(out, 'wb') as f:
		elf.save(f)


parser = argparse.ArgumentParser(description="""
	Sign Qualcomm firmware using test certificates.
	Note: This works only for devices that have secure boot disabled!
	Note2: At the moment the tool only generates the absolute minimum to have
		the firmware accepted by SBL. There is actually no signature generated!
""")
parser.add_argument('type', choices=FW_SW_ID.keys(), help="Firmware type (for SW_ID)")
parser.add_argument('elf', type=argparse.FileType('rb'), help="ELF image to sign")
parser.add_argument('-v', '--version', type=int, choices=[3, 5], default=3, help="MBN header version")
parser.add_argument('-o', '--output', type=Path, help="Output file")
args = parser.parse_args()

with args.elf:
	elf_bytes = args.elf.read()

out = args.output
if not out:
	elf_path = Path(args.elf.name)
	out = elf_path.with_name(elf_path.stem + "-test-signed.mbn")

_sign_elf(elf_bytes, out, args.version, FW_SW_ID[args.type])
