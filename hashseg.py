# SPDX-License-Identifier: GPL-2.0-only AND BSD-3-Clause
# Copyright (C) 2021-2022 Stephan Gerhold (GPL-2.0-only)
# Header format taken from https://git.linaro.org/landing-teams/working/qualcomm/signlk.git
# Copyright (c) 2016, The Linux Foundation. All rights reserved. (BSD-3-Clause)
# See: https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf
from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass
from io import BytesIO
from struct import Struct

import elf
import sign

# A typical Qualcomm firmware might have the following program headers:
#     LOAD off    0x00000800 vaddr 0x86400000 paddr 0x86400000 align 2**11
#          filesz 0x00001000 memsz 0x00001000 flags rwx
#
# The signed version will then look like:
#     NULL off    0x00000000 vaddr 0x00000000 paddr 0x00000000 align 2**0
#          filesz 0x000000e8 memsz 0x00000000 flags --- 7000000
#     NULL off    0x00001000 vaddr 0x86401000 paddr 0x86401000 align 2**12
#          filesz 0x00000988 memsz 0x00001000 flags --- 2200000
#     LOAD off    0x00002000 vaddr 0x86400000 paddr 0x86400000 align 2**11
#          filesz 0x00001000 memsz 0x00001000 flags rwx
#
# The second NULL program header with off 0x1000 and filesz 0x988 is the actual
# "hash table segment" or shortly "hash segment" (see Figure 2 on page 6 in the PDF).
# It contains the MBN header specified below, then a couple of hashes (e.g. SHA256):
#   1. Hash of ELF header and program headers
#   2. Empty hash for hash segment
#   3. Hashes for data of each memory segment (described by program header)
# Finally, it contains an RSA signature and the concatenated certificate chain.
#
# The first NULL program header is never loaded anywhere, because
# vaddr = paddr = memsz = 0. However, the "off" and "filesz" cover exactly
# the ELF header (including all program headers). It is a placeholder so that
# each hash covers the data of exactly one program header.

PHDR_FLAGS_HDR_PLACEHOLDER = 0x7000000  # placeholder for hash over ELF header
PHDR_FLAGS_HASH_SEGMENT = 0x2200000  # hash table segment

EXTRA_PHDRS = 2  # header placeholder + hash segment

# Note: None of the alignments seem to be truly required,
# this could probably be reduced to get smaller file sizes.
HASH_SEG_ALIGN = 0x1000
CERT_CHAIN_ALIGN = 16

SHA256_SIZE = 32
SHA256_EMPTY = b'\0' * SHA256_SIZE


def _align(i: int, alignment: int) -> int:
	mask = max(alignment - 1, 0)
	return (i + mask) & ~mask


@dataclass
class Header:
	version: int  # Header version number
	type: int  # Type of "image" (always 0x3?)
	flash_addr: int  # Location of image in flash (always 0?)
	dest_addr: int  # Physical address of loaded hash segment data
	total_size: int  # = code_size + signature_size + cert_chain_size
	hash_size: int  # Size of SHA256 hashes for each program segment
	signature_addr: int  # Physical address of loaded attestation signature
	signature_size: int  # Size of attestation signature
	cert_chain_addr: int  # Physical address of loaded certificate chain
	cert_chain_size: int  # Size of certificate chain

	FORMAT = Struct('<10L')

	def __init__(self, dest_addr: int, hash_size: int, signature_size: int, cert_chain_size: int):
		self.version = 0
		self.type = 0x3
		self.flash_addr = 0
		self.dest_addr = dest_addr + Header.FORMAT.size
		self.total_size = hash_size + signature_size + cert_chain_size
		self.hash_size = hash_size
		self.signature_addr = self.dest_addr + hash_size
		self.signature_size = signature_size
		self.cert_chain_addr = self.signature_addr + signature_size
		self.cert_chain_size = cert_chain_size

	@property
	def size_with_header(self):
		return Header.FORMAT.size + self.total_size

	def pack(self, hashes: bytes, signature: bytes, cert_chain: bytes) -> bytes:
		assert len(hashes) == self.hash_size
		assert len(signature) == self.signature_size
		assert len(cert_chain) == self.cert_chain_size

		# The hash segment data is header/hashes/cert_chain/signature concatenated
		header = Header.FORMAT.pack(*dataclasses.astuple(self))
		return header + hashes + signature + cert_chain


def generate(elff: elf.Elf, sw_id: int):
	# Drop existing hash segments
	elff.phdrs = [phdr for phdr in elff.phdrs if phdr.p_type != 0 or phdr.p_flags not in
				  [PHDR_FLAGS_HASH_SEGMENT, PHDR_FLAGS_HDR_PLACEHOLDER]]
	assert elff.phdrs, "Need at least one program header"

	# Generate SHA256 hash for all existing segments with data
	hashes = [SHA256_EMPTY] * (len(elff.phdrs) + EXTRA_PHDRS)
	for i, phdr in enumerate(elff.phdrs, start=EXTRA_PHDRS):
		if phdr.data:
			hashes[i] = hashlib.sha256(phdr.data).digest()

	# Generate certificate chain with specified sw_id, and pad it to alignment (not sure why)
	cert_chain = sign.generate_cert_chain(sw_id)
	cert_chain = cert_chain.ljust(_align(len(cert_chain), CERT_CHAIN_ALIGN), b'\xff')
	# cert_chain = b'\00' * CERT_CHAIN_ALIGN  # can be used for testing

	# TODO: Generate actual signature with our generated attestation certificate!
	# There are different signature schemes that could be implemented (RSASSA-PKCS#1 v1.5
	# RSASSA-PSS, ECDSA over P-384) but it's not entirely clear yet which chipsets supports/
	# uses which. The signature does not seem to be checked on devices without secure boot,
	# so just use a dummy value for now.
	signature = b'\xff' * (sign.KEY_BITS // 8)

	# Align maximum end address to get address for hash table header, then generate header
	hash_addr = _align(max(phdr.p_paddr + phdr.p_memsz for phdr in elff.phdrs), HASH_SEG_ALIGN)
	hash_header = Header(hash_addr, len(hashes) * SHA256_SIZE, len(signature), len(cert_chain))
	print(hash_header)

	# Place hash segment at first possible location respecting space for program headers + alignment
	hash_start = _align(elff.total_header_size(EXTRA_PHDRS), HASH_SEG_ALIGN)
	pos = hash_start + hash_header.size_with_header

	# Rearrange all segments according to their alignment
	for phdr in sorted(elff.phdrs, key=lambda phdr: phdr.p_offset):
		if phdr.p_offset and phdr.p_filesz:
			phdr.p_offset = _align(pos, phdr.p_align)
			pos = phdr.p_offset + phdr.p_filesz

	# Insert new hash NULL segment
	hash_phdr = elf.Phdr(0, hash_start, hash_addr, hash_addr, hash_header.size_with_header,
						 _align(hash_header.size_with_header, HASH_SEG_ALIGN),
						 PHDR_FLAGS_HASH_SEGMENT, HASH_SEG_ALIGN)
	elff.phdrs.insert(0, hash_phdr)

	# Insert new ELF header placeholder program header
	hdr_hash_phdr = elf.Phdr(0, 0, 0, 0, 0, 0, PHDR_FLAGS_HDR_PLACEHOLDER, 0)
	elff.phdrs.insert(0, hdr_hash_phdr)

	# Now determine size of ELF header (including program headers)
	hdr_hash_phdr.p_filesz = elff.total_header_size()

	# Recompute attributes to match final output (e.g. adjust e_phnum)
	elff.update()

	# Compute the hash for the ELF header
	with BytesIO() as hdr_io:
		elff.save_header(hdr_io)
		hashes[0] = hashlib.sha256(hdr_io.getbuffer()).digest()

	# And finally, assemble the hash segment
	hash_phdr.data = hash_header.pack(b''.join(hashes), signature, cert_chain)
