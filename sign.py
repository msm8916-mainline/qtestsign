# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2021-2022 Stephan Gerhold
# See https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v1-0.pdf
# Somewhat based on code snippets from https://cryptography.io/en/latest/x509/tutorial.html
from __future__ import annotations

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

KEY_BITS = 2048


def _begin_cert() -> (rsa.RSAPrivateKey, x509.CertificateBuilder):
	key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)
	return key, x509.CertificateBuilder() \
		.public_key(key.public_key()) \
		.serial_number(1) \
		.not_valid_before(datetime.utcnow()) \
		.not_valid_after(datetime.utcnow() + timedelta(seconds=1325391984))


def generate_cert_chain(sw_id: int, sw_size: int) -> bytes:
	# First, create the root CA
	root_name = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, "qtestsign Root CA - NOT SECURE"),
	])
	# only key_cert_sign=True
	root_usage = x509.KeyUsage(False, False, False, False, False, True, False, False, False)
	root_key, builder = _begin_cert()
	root_ski = x509.SubjectKeyIdentifier.from_public_key(root_key.public_key())
	root_cert_der = builder.subject_name(root_name).issuer_name(root_name) \
		.add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True) \
		.add_extension(root_usage, critical=True) \
		.add_extension(root_ski, critical=False) \
		.sign(root_key, hashes.SHA256()) \
		.public_bytes(serialization.Encoding.DER)

	# Now, create the attestation certificate
	att_name = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, "qtestsign Attestation CA - NOT SECURE"),
		# Note: The SW_ID is checked by the firmware on some platforms (even if secure boot
		# is disabled), so it must match the firmware type being signed. Everything else seems
		# to be mostly ignored when secure boot is off and is just added here to match the
		# documentation and better mimic the official firmware.
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "01 %016X SW_ID" % sw_id),
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "02 %016X HW_ID" % 0),
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "03 %016X DEBUG" % 2),  # DISABLED
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "04 %04X OEM_ID" % 0),
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "05 %08X SW_SIZE" % sw_size),
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "06 %04X MODEL_ID" % 0),
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "07 %04X SHA256" % 1),
	])
	# only digital_signature=True
	att_usage = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
	att_key, builder = _begin_cert()
	att_cert_der = builder.subject_name(att_name).issuer_name(root_name) \
		.add_extension(att_usage, critical=True) \
		.add_extension(x509.SubjectKeyIdentifier.from_public_key(att_key.public_key()), critical=False) \
		.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), critical=False) \
		.sign(root_key, hashes.SHA256()) \
		.public_bytes(serialization.Encoding.DER)

	# The certificate chain is the attestation and root certificate concatenated
	# in DER format. Note: The order (first attestation, then root) is important!
	return att_cert_der + root_cert_der
