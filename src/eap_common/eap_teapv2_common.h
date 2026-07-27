/*
 * EAP-TEAPV2 definitions (draft-ietf-emu-teapv2)
 * Copyright (c) 2004-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_TEAPV2_H
#define EAP_TEAPV2_H

#define EAP_TEAPV2_VERSION 1
#define EAP_TEAPV2_KEY_LEN 64
/*
 * draft-ietf-emu-teapv2 Section 4.2: TEAPv2 implementations MUST support and
 * MUST NOT exceed an EAP MTU of 1280 octets.
 */
#define EAP_TEAPV2_MAX_LEN 1280
/*
 * draft-ietf-emu-teapv2 Section 3.3:
 *   RoundSeed         = PrevRoundKey[40] || MSK[32] || EMSK[32]   (104 octets)
 *   DerivedKey        = TLS-Exporter(RoundSeed, 72)               (RoundKey[40] || CMK[32])
 */
#define EAP_TEAPV2_ROUNDKEY_LEN 40
#define EAP_TEAPV2_MSK_HALF_LEN 32
#define EAP_TEAPV2_EMSK_HALF_LEN 32
#define EAP_TEAPV2_ROUNDSEED_LEN (EAP_TEAPV2_ROUNDKEY_LEN + \
				  EAP_TEAPV2_MSK_HALF_LEN + \
				  EAP_TEAPV2_EMSK_HALF_LEN)
#define EAP_TEAPV2_CMK_LEN 32
#define EAP_TEAPV2_DERIVED_KEY_LEN (EAP_TEAPV2_ROUNDKEY_LEN + \
				    EAP_TEAPV2_CMK_LEN)
#define EAP_TEAPV2_COMPOUND_MAC_LEN 20
#define EAP_TEAPV2_NONCE_LEN 32

#define TEAPV2_TLS_EXPORTER_LABEL_SKS "EXPORTER: teap session key seed"
/* draft-ietf-emu-teapv2 Section 3.3.2 */
#define TEAPV2_TLS_EXPORTER_LABEL_IMCK \
	"EXPORTER: TEAPv2 Inner Methods Compound Keys"

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct teapv2_tlv_hdr {
	be16 tlv_type;
	be16 length;
} STRUCT_PACKED;

/* Result TLV and Intermediate-Result TLV */
struct teapv2_tlv_result {
	be16 tlv_type;
	be16 length;
	be16 status;
	/* for Intermediate-Result TLV, followed by optional TLVs */
} STRUCT_PACKED;

struct teapv2_tlv_nak {
	be16 tlv_type;
	be16 length;
	be32 vendor_id;
	be16 nak_type;
	/* followed by optional TLVs */
} STRUCT_PACKED;

struct teapv2_tlv_crypto_binding {
	be16 tlv_type; /* TLV Type[14b] and M/R flags */
	be16 length;
	u8 reserved;
	u8 version;
	u8 received_version;
	u8 subtype; /* Flags[4b] and Sub-Type[4b] */
	u8 nonce[EAP_TEAPV2_NONCE_LEN];
	u8 emsk_compound_mac[EAP_TEAPV2_COMPOUND_MAC_LEN];
	u8 msk_compound_mac[EAP_TEAPV2_COMPOUND_MAC_LEN];
} STRUCT_PACKED;

/* draft-ietf-emu-teapv2 Section 3.3.1: RoundSeed used as the context for the
 * TLS-Exporter that derives the RoundKey and CMK for each inner round. */
struct teapv2_round_seed {
	u8 prev_round_key[EAP_TEAPV2_ROUNDKEY_LEN];
	u8 msk[EAP_TEAPV2_MSK_HALF_LEN];
	u8 emsk[EAP_TEAPV2_EMSK_HALF_LEN];
} STRUCT_PACKED;

enum teapv2_request_action {
	TEAPV2_REQUEST_ACTION_PROCESS_TLV = 1,
};

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#define TEAPV2_CRYPTO_BINDING_SUBTYPE_REQUEST 0
#define TEAPV2_CRYPTO_BINDING_SUBTYPE_RESPONSE 1

#define TEAPV2_CRYPTO_BINDING_MSK_CMAC 2


/* draft-ietf-emu-teapv2 Section 4.2.1: General TLV Format */
enum teapv2_tlv_types {
	TEAPV2_TLV_AUTHORITY_ID = 1,
	TEAPV2_TLV_IDENTITY_TYPE = 2,
	TEAPV2_TLV_RESULT = 3,
	TEAPV2_TLV_NAK = 4,
	TEAPV2_TLV_ERROR = 5,
	TEAPV2_TLV_CHANNEL_BINDING = 6,
	TEAPV2_TLV_VENDOR_SPECIFIC = 7,
	TEAPV2_TLV_REQUEST_ACTION = 8,
	TEAPV2_TLV_EAP_PAYLOAD = 9,
	TEAPV2_TLV_INTERMEDIATE_RESULT = 10,
	TEAPV2_TLV_CRYPTO_BINDING = 12,
	TEAPV2_TLV_BASIC_PASSWORD_AUTH_REQ = 13,
	TEAPV2_TLV_BASIC_PASSWORD_AUTH_RESP = 14,
	TEAPV2_TLV_PKCS7 = 15,
	TEAPV2_TLV_PKCS10 = 16,
	TEAPV2_TLV_TRUSTED_SERVER_ROOT = 17,
	TEAPV2_TLV_CSR_ATTRS = 18,
};

enum teapv2_tlv_result_status {
	TEAPV2_STATUS_SUCCESS = 1,
	TEAPV2_STATUS_FAILURE = 2
};

/* Identity-Type values within Identity-Type TLV */
enum teapv2_identity_types {
	TEAPV2_IDENTITY_TYPE_USER = 1,
	TEAPV2_IDENTITY_TYPE_MACHINE = 2,
};

#define TEAPV2_TLV_MANDATORY 0x8000
#define TEAPV2_TLV_TYPE_MASK 0x3fff

/* RFC 7170, 4.2.6: Error TLV */
enum teapv2_error_codes {
	TEAPV2_ERROR_INNER_METHOD = 1001,
	TEAPV2_ERROR_UNSPEC_AUTH_INFRA_PROBLEM = 1002,
	TEAPV2_ERROR_UNSPEC_AUTHENTICATION_FAILURE = 1003,
	TEAPV2_ERROR_UNSPEC_AUTHORIZATION_FAILURE = 1004,
	TEAPV2_ERROR_USER_ACCOUNT_CRED_UNAVAILABLE = 1005,
	TEAPV2_ERROR_USER_ACCOUNT_EXPIRED = 1006,
	TEAPV2_ERROR_USER_ACCOUNT_LOCKED_TRY_AGAIN_LATER = 1007,
	TEAPV2_ERROR_USER_ACCOUNT_LOCKED_ADMIN_REQ = 1008,
	TEAPV2_ERROR_TUNNEL_COMPROMISE_ERROR = 2001,
	TEAPV2_ERROR_UNEXPECTED_TLVS_EXCHANGED = 2002,
};

struct wpabuf;
struct tls_connection;

struct eap_teapv2_tlv_parse {
	u8 *eap_payload_tlv;
	size_t eap_payload_tlv_len;
	struct teapv2_tlv_crypto_binding *crypto_binding;
	size_t crypto_binding_len;
	int iresult;
	int result;
	u8 *nak;
	u8 request_action;
	u16 request_action_tlvs_type;
	u8 *basic_auth_req;
	size_t basic_auth_req_len;
	u8 *basic_auth_resp;
	size_t basic_auth_resp_len;
	u16 identity_type;
	u8 *pkcs10;
	size_t pkcs10_len;
	u8 *pkcs7;
	size_t pkcs7_len;
	u8 *trusted_server_root;
	size_t trusted_server_root_len;
	u8 *csr_attrs;
	size_t csr_attrs_len;
};

void eap_teapv2_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len);
void eap_teapv2_put_tlv(struct wpabuf *buf, u16 type, const void *data, u16 len);
void eap_teapv2_put_tlv_buf(struct wpabuf *buf, u16 type,
			  const struct wpabuf *data);
struct wpabuf * eap_teapv2_tlv_eap_payload(struct wpabuf *buf);
int eap_teapv2_derive_eap_msk(const struct teapv2_round_seed *rs, u8 *msk);
int eap_teapv2_derive_eap_emsk(const struct teapv2_round_seed *rs, u8 *emsk);
int eap_teapv2_derive_round_key(void *tls_ctx, struct tls_connection *conn,
				struct teapv2_round_seed *rs,
				const u8 *msk, size_t msk_len,
				const u8 *emsk, size_t emsk_len,
				u8 *cmk);
int eap_teapv2_compound_mac(u16 tls_cs, const struct teapv2_tlv_crypto_binding *cb,
			  const struct wpabuf *server_outer_tlvs,
			  const struct wpabuf *peer_outer_tlvs,
			  const u8 *cmk, u8 *compound_mac);
int eap_teapv2_parse_tlv(struct eap_teapv2_tlv_parse *tlv,
		       int tlv_type, u8 *pos, size_t len);
const char * eap_teapv2_tlv_type_str(enum teapv2_tlv_types type);
struct wpabuf * eap_teapv2_tlv_result(int status, int intermediate);
struct wpabuf * eap_teapv2_tlv_error(enum teapv2_error_codes error);
struct wpabuf * eap_teapv2_tlv_identity_type(enum teapv2_identity_types id);

#endif /* EAP_TEAPV2_H */
