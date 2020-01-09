// Copyright (C) 2020 Network State.
// All rights reserved.
// Released under 'Source Available License'
#pragma once
#include "TLS.h"

constexpr UINT32 CIPHER_EXPANSION_MAX = 256;

enum class EXTENSION_TYPE : UINT16
{
	server_name = 0,                             /* RFC 6066 */
	max_fragment_length = 1,                     /* RFC 6066 */
	status_request = 5,                          /* RFC 6066 */
	supported_groups = 10,                       /* RFC 8422, 7919 */
	ec_point_formats = 11,                       /* RFC 8422 */
	signature_algorithms = 13,                   /* RFC 8446 */
	use_srtp = 14,                               /* RFC 5764 */
	heartbeat = 15,                              /* RFC 6520 */
	application_layer_protocol_negotiation = 16, /* RFC 7301 */
	signed_certificate_timestamp = 18,           /* RFC 6962 */
	client_certificate_type = 19,                /* RFC 7250 */
	server_certificate_type = 20,                /* RFC 7250 */
	padding = 21,                                /* RFC 7685 */
	pre_shared_key = 41,                         /* RFC 8446 */
	early_data = 42,                             /* RFC 8446 */
	supported_versions = 43,                     /* RFC 8446 */
	cookie = 44,                                 /* RFC 8446 */
	psk_key_exchange_modes = 45,                 /* RFC 8446 */
	certificate_authorities = 47,                /* RFC 8446 */
	oid_filters = 48,                            /* RFC 8446 */
	post_handshake_auth = 49,                    /* RFC 8446 */
	signature_algorithms_cert = 50,              /* RFC 8446 */
	key_share = 51,                              /* RFC 8446 */
};

enum class MESSAGE_TYPE : UINT8
{
	hello_request = 0,
	client_hello = 1,
	server_hello = 2,
	hello_verify_request = 3,
	new_session_ticket = 4,
	end_of_early_data = 5,
	encrypted_extensions = 8,
	certificate = 11,
	server_key_exchange = 12,
	certificate_request = 13,
	server_hello_done = 14,
	certificate_verify = 15,
	client_key_exchange = 16,
	finished = 20,
	certificate_url = 21,
	certificate_status = 22,
	key_update = 24,
	message_hash = 254,
	unknown = 255,
};

enum class RECORD_TYPE : UINT8
{
	invalid = 0,
	change_cipher_spec = 20,
	alert = 21,
	handshake = 22,
	application_data = 23,
	heaart_beat = 24,
};

enum class TLS_VERSION : UINT16
{
	TLS10 = 0x0301,
	TLS12 = 0x0303,
	TLS13 = 0x0304,
	DTLS12 = 0xFEFD,
};

enum class SUPPORTED_GROUPS : UINT16
{
	/* Elliptic Curve Groups (ECDHE) */
	secp256r1 = 0x0017,
	secp384r1 = 0x0018,
	secp521r1 = 0x0019,

	x25519 = 0x001D,
	x448 = 0x001E,

	/* Finite Field Groups (DHE) */
	ffdhe2048 = 0x0100,
	ffdhe3072 = 0x0101,
	ffdhe4096 = 0x0102,
	ffdhe6144 = 0x0103,
	ffdhe8192 = 0x0104,
};

enum class SIGNATURE_SCHEME : UINT16
{
	/* RSASSA-PKCS1-v1_5 algorithms */
	rsa_pkcs1_sha256 = 0x0401,
	rsa_pkcs1_sha384 = 0x0501,
	rsa_pkcs1_sha512 = 0x0601,

	/* ECDSA algorithms */
	ecdsa_secp256r1_sha256 = 0x0403,
	ecdsa_secp384r1_sha384 = 0x0503,
	ecdsa_secp521r1_sha512 = 0x0603,

	/* RSASSA-PSS algorithms with public key OID rsaEncryption */
	rsa_pss_rsae_sha256 = 0x0804,
	rsa_pss_rsae_sha384 = 0x0805,
	rsa_pss_rsae_sha512 = 0x0806,

	/* EdDSA algorithms */
	ed25519 = 0x0807,
	ed448 = 0x0808,

	/* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
	rsa_pss_pss_sha256 = 0x0809,
	rsa_pss_pss_sha384 = 0x080a,
	rsa_pss_pss_sha512 = 0x080b,

	/* Legacy algorithms */
	rsa_pkcs1_sha1 = 0x0201,
	ecdsa_sha1 = 0x0203,
};

enum class CLIENT_CERTIFICATE_TYPE : UINT8
{
	rsa_sign = 1,
	dss_sign = 2, 
	rsa_fixed_dh = 3, 
	dss_fixed_dh = 4,
	ecdsa_sign = 64, // RFC4492
	rsa_fixed_ecdh = 65,
	ecdsa_fixed_ecdh = 66,
};

enum class CIPHER_SUITE : UINT16
{
	TLS_AES_128_GCM_SHA256 = 0x1301,
	TLS_AES_256_GCM_SHA384 = 0x1302,
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
	TLS_AES_128_CCM_SHA256 = 0x1304,
	TLS_AES_128_CCM_8_SHA256 = 0x1305,

	// for TLS 1.2
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,

};

enum class SRTP_PROTECTION_PROFILE : UINT16
{
	SRTP_AEAD_AES_128_GCM = 0x0007,
	SRTP_AEAD_AES_256_GCM = 0x0008,
};

enum class EC_CURVE_TYPE : UINT8
{
	explicit_prime = 1,
	explicit_char2 = 2,
	named_curve = 3,
};

enum class ALERT_LEVEL : UINT8
{
	warning = 1,
	fatal = 2,
};

enum class ALERT_DESCRIPTION : UINT8
{
	close_notify = 0,
	unexpected_message = 10,
	bad_record_mac = 20,
	record_overflow = 22,
	handshake_failure = 40,
	bad_certificate = 42,
	unsupported_certificate = 43,
	certificate_revoked = 44,
	certificate_expired = 45,
	certificate_unknown = 46,
	illegal_parameter = 47,
	unknown_ca = 48,
	access_denied = 49,
	decode_error = 50,
	decrypt_error = 51,
	protocol_version = 70,
	insufficient_security = 71,
	internal_error = 80,
	inappropriate_fallback = 86,
	user_canceled = 90,
	missing_extension = 109,
	unsupported_extension = 110,
	unrecognized_name = 112,
	bad_certificate_status_response = 113,
	unknown_psk_identity = 115,
	certificate_required = 116,
	no_application_protocol = 120,
};

