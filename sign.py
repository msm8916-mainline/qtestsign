# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2021 Stephan Gerhold
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


def generate_cert_chain(sw_id: int) -> bytes:
	# First, create the root CA
	root_name = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, "Generated Test Root CA - NOT SECURE"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "qtestsign"),
	])
	root_key, builder = _begin_cert()
	root_cert_der = builder.subject_name(root_name).issuer_name(root_name) \
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) \
		.sign(root_key, hashes.SHA256()) \
		.public_bytes(serialization.Encoding.DER)

	# Now, create the attestation certificate
	att_name = x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, "Generated Test Attestation CA - NOT SECURE"),
		x509.NameAttribute(NameOID.ORGANIZATION_NAME, "qtestsign"),
		# Note: Apparently the SW_ID *must* be correct for the firmware type
		# to pass the validation in SBL.
		x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "01 %016X SW_ID" % sw_id),
	])
	# only digital_signature=True
	att_usage = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
	att_key, builder = _begin_cert()
	att_cert_der = builder.subject_name(att_name).issuer_name(root_name) \
		.add_extension(att_usage, critical=True) \
		.sign(root_key, hashes.SHA256()) \
		.public_bytes(serialization.Encoding.DER)

	# The certificate chain is the attestaton and root certificate concatenated
	# in DER format. Note: The order (first attestation, then root) is important!
	return att_cert_der + root_cert_der
