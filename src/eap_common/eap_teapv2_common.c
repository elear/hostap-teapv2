/*
 * EAP-TEAPV2 common helper functions (draft-ietf-emu-teapv2)
 * Copyright (c) 2008-2019, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/sha256.h"
#include "crypto/sha384.h"
#include "crypto/tls.h"
#include "eap_defs.h"
#include "eap_teapv2_common.h"


void eap_teapv2_put_tlv_hdr(struct wpabuf *buf, u16 type, u16 len)
{
	struct teapv2_tlv_hdr hdr;

	hdr.tlv_type = host_to_be16(type);
	hdr.length = host_to_be16(len);
	wpabuf_put_data(buf, &hdr, sizeof(hdr));
}


void eap_teapv2_put_tlv(struct wpabuf *buf, u16 type, const void *data, u16 len)
{
	eap_teapv2_put_tlv_hdr(buf, type, len);
	wpabuf_put_data(buf, data, len);
}


void eap_teapv2_put_tlv_buf(struct wpabuf *buf, u16 type,
			  const struct wpabuf *data)
{
	eap_teapv2_put_tlv_hdr(buf, type, wpabuf_len(data));
	wpabuf_put_buf(buf, data);
}


struct wpabuf * eap_teapv2_tlv_eap_payload(struct wpabuf *buf)
{
	struct wpabuf *e;

	if (!buf)
		return NULL;

	/* Encapsulate EAP packet in EAP-Payload TLV */
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Add EAP-Payload TLV");
	e = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) + wpabuf_len(buf));
	if (!e) {
		wpa_printf(MSG_ERROR,
			   "EAP-TEAPV2: Failed to allocate memory for TLV encapsulation");
		wpabuf_free(buf);
		return NULL;
	}
	eap_teapv2_put_tlv_buf(e, TEAPV2_TLV_MANDATORY | TEAPV2_TLV_EAP_PAYLOAD, buf);
	wpabuf_free(buf);

	/* TODO: followed by optional TLVs associated with the EAP packet */

	return e;
}


int eap_teapv2_derive_eap_msk(const struct teapv2_round_seed *rs, u8 *msk)
{
	/*
	 * draft-ietf-emu-teapv2 Section 3.5:
	 * MSK = first 64 octets of
	 *       TLS-PRF(RoundSeed, "Session Key Generating Function")
	 */
	if (tls_prf_sha256((const u8 *) rs, EAP_TEAPV2_ROUNDSEED_LEN,
			   "Session Key Generating Function", (u8 *) "", 0,
			   msk, EAP_TEAPV2_KEY_LEN) < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: Derived key (MSK)",
			msk, EAP_TEAPV2_KEY_LEN);
	return 0;
}


int eap_teapv2_derive_eap_emsk(const struct teapv2_round_seed *rs, u8 *emsk)
{
	/*
	 * draft-ietf-emu-teapv2 Section 3.5:
	 * EMSK = first 64 octets of
	 *        TLS-PRF(RoundSeed, "Extended Session Key Generating Function")
	 */
	if (tls_prf_sha256((const u8 *) rs, EAP_TEAPV2_ROUNDSEED_LEN,
			   "Extended Session Key Generating Function",
			   (u8 *) "", 0, emsk, EAP_EMSK_LEN) < 0)
		return -1;
	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: Derived key (EMSK)",
			emsk, EAP_EMSK_LEN);
	return 0;
}


int eap_teapv2_derive_round_key(void *tls_ctx, struct tls_connection *conn,
				struct teapv2_round_seed *rs,
				const u8 *msk, size_t msk_len,
				const u8 *emsk, size_t emsk_len,
				u8 *cmk)
{
	if (TEST_FAIL())
		return -1;
	/*
	 * draft-ietf-emu-teapv2 Section 3.3.1 - 3.3.3:
	 *
	 *   RoundSeed  = PrevRoundKey[40] || MSK[32] || EMSK[32]
	 *   DerivedKey = TLS-Exporter(
	 *                    "EXPORTER: TEAPv2 Inner Methods Compound Keys",
	 *                    RoundSeed, 72)
	 *   RoundKey   = first 40 octets of DerivedKey
	 *   CMK        = last  32 octets of DerivedKey
	 *
	 * After DerivedKey is calculated, RoundSeed is updated for the next
	 * round: RoundKey is copied to PrevRoundKey, MSK/EMSK stay in place.
	 */
	u8 derived[EAP_TEAPV2_DERIVED_KEY_LEN];
	size_t copy_len;

	/* Fill in MSK/EMSK halves (zero-padded/truncated to 32 octets each). */
	os_memset(rs->msk, 0, sizeof(rs->msk));
	if (msk && msk_len > 0) {
		copy_len = msk_len > sizeof(rs->msk) ? sizeof(rs->msk) : msk_len;
		os_memcpy(rs->msk, msk, copy_len);
	}
	os_memset(rs->emsk, 0, sizeof(rs->emsk));
	if (emsk && emsk_len > 0) {
		copy_len = emsk_len > sizeof(rs->emsk) ?
			sizeof(rs->emsk) : emsk_len;
		os_memcpy(rs->emsk, emsk, copy_len);
	}

	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: RoundSeed",
			(const u8 *) rs, EAP_TEAPV2_ROUNDSEED_LEN);

	if (tls_connection_export_key(tls_ctx, conn,
				      TEAPV2_TLS_EXPORTER_LABEL_IMCK,
				      (const u8 *) rs,
				      EAP_TEAPV2_ROUNDSEED_LEN,
				      derived,
				      EAP_TEAPV2_DERIVED_KEY_LEN) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: TLS-Exporter for RoundKey/CMK failed");
		return -1;
	}

	os_memcpy(cmk, derived + EAP_TEAPV2_ROUNDKEY_LEN,
		  EAP_TEAPV2_CMK_LEN);
	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: CMK",
			cmk, EAP_TEAPV2_CMK_LEN);

	/* Update RoundSeed for the next round (Section 3.3.3). */
	os_memcpy(rs->prev_round_key, derived, EAP_TEAPV2_ROUNDKEY_LEN);
	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: Updated PrevRoundKey",
			rs->prev_round_key, EAP_TEAPV2_ROUNDKEY_LEN);

	forced_memzero(derived, sizeof(derived));
	return 0;
}


static int tls_cipher_suite_match(const u16 *list, size_t count, u16 cs)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (list[i] == cs)
			return 1;
	}

	return 0;
}


static int tls_cipher_suite_mac_sha256(u16 cs)
{
	static const u16 sha256_cs[] = {
		0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0067, 0x0068, 0x0069,
		0x006a, 0x006b, 0x006c, 0x006d, 0x009c, 0x009e, 0x00a0, 0x00a2,
		0x00a4, 0x00a6, 0x00a8, 0x00aa, 0x00ac, 0x00ae, 0x00b2, 0x00b6,
		0x00ba, 0x00bb, 0x00bc, 0x00bd, 0x00be, 0x00bd, 0x00be, 0x00be,
		0x00bf, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5,
		0x1301, 0x1303, 0x1304, 0x1305,
		0xc023, 0xc025, 0xc027, 0xc029, 0xc02b, 0xc02d, 0xc02f, 0xc031,
		0xc037, 0xc03c, 0xc03e, 0xc040, 0xc040, 0xc042, 0xc044, 0xc046,
		0xc048, 0xc04a, 0xc04c, 0xc04e, 0xc050, 0xc052, 0xc054, 0xc056,
		0xc058, 0xc05a, 0xc05c, 0xc05e, 0xc060, 0xc062, 0xc064, 0xc066,
		0xc068, 0xc06a, 0xc06c, 0xc06e, 0xc070, 0xc072, 0xc074, 0xc076,
		0xc078, 0xc07a, 0xc07c, 0xc07e, 0xc080, 0xc082, 0xc084, 0xc086,
		0xc088, 0xc08a, 0xc08c, 0xc08e, 0xc090, 0xc092, 0xc094, 0xc096,
		0xc098, 0xc09a, 0xc0b0, 0xc0b2, 0xc0b4,
		0xcca8, 0xcca9, 0xccaa, 0xccab, 0xccac, 0xccad, 0xccae,
		0xd001, 0xd003, 0xd005
	};

	return tls_cipher_suite_match(sha256_cs, ARRAY_SIZE(sha256_cs), cs);
}


static int tls_cipher_suite_mac_sha384(u16 cs)
{
	static const u16 sha384_cs[] = {
		0x009d, 0x009f, 0x00a1, 0x00a3, 0x00a5, 0x00a7, 0x00a9, 0x00ab,
		0x00ad, 0x00af, 0x00b3, 0x00b7, 0x1302,
		0xc024, 0xc026, 0xc028, 0xc02a, 0xc02c, 0xc02e, 0xc030, 0xc032,
		0xc038, 0xc03d, 0xc03f, 0xc041, 0xc043, 0xc045, 0xc047, 0xc049,
		0xc04b, 0xc04d, 0xc04f, 0xc051, 0xc053, 0xc055, 0xc057, 0xc059,
		0xc05b, 0xc05d, 0xc05f, 0xc061, 0xc063, 0xc065, 0xc067, 0xc069,
		0xc06b, 0xc06d, 0xc06f, 0xc071, 0xc073, 0xc075, 0xc077, 0xc079,
		0xc07b, 0xc07d, 0xc07f, 0xc081, 0xc083, 0xc085, 0xc087, 0xc089,
		0xc08b, 0xc08d, 0xc08f, 0xc091, 0xc093, 0xc095, 0xc097, 0xc099,
		0xc09b, 0xc0b1, 0xc0b3, 0xc0b5,
		0xd002
	};

	return tls_cipher_suite_match(sha384_cs, ARRAY_SIZE(sha384_cs), cs);
}


static int eap_teapv2_tls_mac(u16 tls_cs, const u8 *cmk, size_t cmk_len,
			    const u8 *buffer, size_t buffer_len,
			    u8 *mac, size_t mac_len)
{
	int res;
	u8 tmp[48];

	os_memset(tmp, 0, sizeof(tmp));
	os_memset(mac, 0, mac_len);

	/* draft-ietf-emu-teapv2 requires TLS 1.3, so only SHA-256 and SHA-384
	 * MAC algorithms need to be supported here. */
	if (tls_cipher_suite_mac_sha384(tls_cs)) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: MAC algorithm: HMAC-SHA384");
		res = hmac_sha384(cmk, cmk_len, buffer, buffer_len, tmp);
	} else if (tls_cipher_suite_mac_sha256(tls_cs)) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: MAC algorithm: HMAC-SHA256");
		res = hmac_sha256(cmk, cmk_len, buffer, buffer_len, tmp);
	} else {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Unsupported TLS cipher suite 0x%04x",
			   tls_cs);
		res = -1;
	}
	if (res < 0)
		return res;

	if (mac_len > sizeof(tmp))
		mac_len = sizeof(tmp);
	os_memcpy(mac, tmp, mac_len);
	return 0;
}


int eap_teapv2_compound_mac(u16 tls_cs, const struct teapv2_tlv_crypto_binding *cb,
			  const struct wpabuf *server_outer_tlvs,
			  const struct wpabuf *peer_outer_tlvs,
			  const u8 *cmk, u8 *compound_mac)
{
	u8 *pos, *buffer;
	size_t bind_len, buffer_len;
	struct teapv2_tlv_crypto_binding *tmp_cb;
	int res;

	/* draft-ietf-emu-teapv2 Section 3.4 (Compound MAC) */
	bind_len = sizeof(struct teapv2_tlv_hdr) + be_to_host16(cb->length);
	buffer_len = bind_len + 1;
	if (server_outer_tlvs)
		buffer_len += wpabuf_len(server_outer_tlvs);
	if (peer_outer_tlvs)
		buffer_len += wpabuf_len(peer_outer_tlvs);
	buffer = os_malloc(buffer_len);
	if (!buffer)
		return -1;

	pos = buffer;
	/* 1. The entire Crypto-Binding TLV attribute with both the EMSK and MSK
	 * Compound MAC fields zeroed out. */
	os_memcpy(pos, cb, bind_len);
	pos += bind_len;
	tmp_cb = (struct teapv2_tlv_crypto_binding *) buffer;
	os_memset(tmp_cb->emsk_compound_mac, 0, EAP_TEAPV2_COMPOUND_MAC_LEN);
	os_memset(tmp_cb->msk_compound_mac, 0, EAP_TEAPV2_COMPOUND_MAC_LEN);

	/* 2. The EAP Type sent by the other party in the first TEAPV2 message. */
	/* This is supposed to be the EAP Type sent by the other party in the
	 * first TEAPV2 message, but since we cannot get here without having
	 * successfully negotiated use of TEAPV2, this can only be the fixed EAP
	 * Type of TEAPV2. */
	*pos++ = EAP_TYPE_TEAPV2;

	/* 3. All the Outer TLVs from the first TEAPV2 message sent by EAP server
	 * to peer. */
	if (server_outer_tlvs) {
		os_memcpy(pos, wpabuf_head(server_outer_tlvs),
			  wpabuf_len(server_outer_tlvs));
		pos += wpabuf_len(server_outer_tlvs);
	}

	/* 4. All the Outer TLVs from the first TEAPV2 message sent by the peer to
	 * the EAP server. */
	if (peer_outer_tlvs) {
		os_memcpy(pos, wpabuf_head(peer_outer_tlvs),
			  wpabuf_len(peer_outer_tlvs));
		pos += wpabuf_len(peer_outer_tlvs);
	}

	buffer_len = pos - buffer;

	wpa_hexdump_key(MSG_MSGDUMP,
			"EAP-TEAPV2: CMK for Compound MAC calculation",
			cmk, EAP_TEAPV2_CMK_LEN);
	wpa_hexdump(MSG_MSGDUMP,
		    "EAP-TEAPV2: BUFFER for Compound MAC calculation",
		    buffer, buffer_len);
	res = eap_teapv2_tls_mac(tls_cs, cmk, EAP_TEAPV2_CMK_LEN,
			       buffer, buffer_len,
			       compound_mac, EAP_TEAPV2_COMPOUND_MAC_LEN);
	os_free(buffer);

	return res;
}


int eap_teapv2_parse_tlv(struct eap_teapv2_tlv_parse *tlv,
		       int tlv_type, u8 *pos, size_t len)
{
	switch (tlv_type) {
	case TEAPV2_TLV_IDENTITY_TYPE:
		if (len < 2) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short Identity-Type TLV");
			tlv->result = TEAPV2_STATUS_FAILURE;
			break;
		}
		tlv->identity_type = WPA_GET_BE16(pos);
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Identity-Type: %u",
			   tlv->identity_type);
		break;
	case TEAPV2_TLV_RESULT:
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Result TLV", pos, len);
		if (tlv->result) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Result TLV in the message");
			tlv->result = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		if (len < 2) {
			wpa_printf(MSG_INFO, "EAP-TEAPV2: Too short Result TLV");
			tlv->result = TEAPV2_STATUS_FAILURE;
			break;
		}
		tlv->result = WPA_GET_BE16(pos);
		if (tlv->result != TEAPV2_STATUS_SUCCESS &&
		    tlv->result != TEAPV2_STATUS_FAILURE) {
			wpa_printf(MSG_INFO, "EAP-TEAPV2: Unknown Result %d",
				   tlv->result);
			tlv->result = TEAPV2_STATUS_FAILURE;
		}
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Result: %s",
			   tlv->result == TEAPV2_STATUS_SUCCESS ?
			   "Success" : "Failure");
		break;
	case TEAPV2_TLV_NAK:
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: NAK TLV", pos, len);
		if (len < 6) {
			wpa_printf(MSG_INFO, "EAP-TEAPV2: Too short NAK TLV");
			tlv->result = TEAPV2_STATUS_FAILURE;
			break;
		}
		tlv->nak = pos;
		break;
	case TEAPV2_TLV_ERROR:
		if (len < 4) {
			wpa_printf(MSG_INFO, "EAP-TEAPV2: Too short Error TLV");
			tlv->result = TEAPV2_STATUS_FAILURE;
			break;
		}
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Error: %u",
			   WPA_GET_BE32(pos));
		break;
	case TEAPV2_TLV_REQUEST_ACTION:
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Request-Action TLV",
			    pos, len);
		if (tlv->request_action) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Request-Action TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		if (len < 2) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short Request-Action TLV");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			break;
		}
		tlv->request_action = pos[1];
		if (len >= 4)
			tlv->request_action_tlvs_type =
				WPA_GET_BE16(pos + 2) & TEAPV2_TLV_TYPE_MASK;
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Request-Action: Status=%u Action=%u",
			   pos[0], tlv->request_action);
		break;
	case TEAPV2_TLV_EAP_PAYLOAD:
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: EAP-Payload TLV",
			    pos, len);
		if (tlv->eap_payload_tlv) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one EAP-Payload TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		tlv->eap_payload_tlv = pos;
		tlv->eap_payload_tlv_len = len;
		break;
	case TEAPV2_TLV_INTERMEDIATE_RESULT:
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Intermediate-Result TLV",
			    pos, len);
		if (len < 2) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short Intermediate-Result TLV");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			break;
		}
		if (tlv->iresult) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Intermediate-Result TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		tlv->iresult = WPA_GET_BE16(pos);
		if (tlv->iresult != TEAPV2_STATUS_SUCCESS &&
		    tlv->iresult != TEAPV2_STATUS_FAILURE) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Unknown Intermediate Result %d",
				   tlv->iresult);
			tlv->iresult = TEAPV2_STATUS_FAILURE;
		}
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Intermediate Result: %s",
			   tlv->iresult == TEAPV2_STATUS_SUCCESS ?
			   "Success" : "Failure");
		break;
	case TEAPV2_TLV_CRYPTO_BINDING:
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Crypto-Binding TLV",
			    pos, len);
		if (tlv->crypto_binding) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Crypto-Binding TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		tlv->crypto_binding_len = sizeof(struct teapv2_tlv_hdr) + len;
		if (tlv->crypto_binding_len < sizeof(*tlv->crypto_binding)) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short Crypto-Binding TLV");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		tlv->crypto_binding = (struct teapv2_tlv_crypto_binding *)
			(pos - sizeof(struct teapv2_tlv_hdr));
		break;
	case TEAPV2_TLV_BASIC_PASSWORD_AUTH_REQ:
		wpa_hexdump_ascii(MSG_MSGDUMP,
				  "EAP-TEAPV2: Basic-Password-Auth-Req TLV",
				  pos, len);
		if (tlv->basic_auth_req) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Basic-Password-Auth-Req TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		tlv->basic_auth_req = pos;
		tlv->basic_auth_req_len = len;
		break;
	case TEAPV2_TLV_BASIC_PASSWORD_AUTH_RESP:
		wpa_hexdump_ascii(MSG_MSGDUMP,
				  "EAP-TEAPV2: Basic-Password-Auth-Resp TLV",
				  pos, len);
		if (tlv->basic_auth_resp) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Basic-Password-Auth-Resp TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		tlv->basic_auth_resp = pos;
		tlv->basic_auth_resp_len = len;
		break;
	case TEAPV2_TLV_PKCS7:
		if (tlv->pkcs7) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one PKCS#7 TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: PKCS#7 TLV", pos, len);
		tlv->pkcs7 = pos;
		tlv->pkcs7_len = len;
		break;
	case TEAPV2_TLV_PKCS10:
		if (tlv->pkcs10) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one PKCS#10 TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: PKCS#10 TLV", pos, len);
		tlv->pkcs10 = pos;
		tlv->pkcs10_len = len;
		break;
	case TEAPV2_TLV_TRUSTED_SERVER_ROOT:
		if (tlv->trusted_server_root) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one Trusted-Server-Root TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Trusted-Server-Root TLV",
			   pos, len);
		tlv->trusted_server_root = pos;
		tlv->trusted_server_root_len = len;
		break;
	case TEAPV2_TLV_CSR_ATTRS:
		if (tlv->csr_attrs) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: More than one CSR-Attributes TLV in the message");
			tlv->iresult = TEAPV2_STATUS_FAILURE;
			return -2;
		}
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: CSR-Attributes TLV",
			   pos, len);
		tlv->csr_attrs = pos;
		tlv->csr_attrs_len = len;
		break;
	default:
		/* Unknown TLV */
		return -1;
	}

	return 0;
}


const char * eap_teapv2_tlv_type_str(enum teapv2_tlv_types type)
{
	switch (type) {
	case TEAPV2_TLV_AUTHORITY_ID:
		return "Authority-ID";
	case TEAPV2_TLV_IDENTITY_TYPE:
		return "Identity-Type";
	case TEAPV2_TLV_RESULT:
		return "Result";
	case TEAPV2_TLV_NAK:
		return "NAK";
	case TEAPV2_TLV_ERROR:
		return "Error";
	case TEAPV2_TLV_CHANNEL_BINDING:
		return "Channel-Binding";
	case TEAPV2_TLV_VENDOR_SPECIFIC:
		return "Vendor-Specific";
	case TEAPV2_TLV_REQUEST_ACTION:
		return "Request-Action";
	case TEAPV2_TLV_EAP_PAYLOAD:
		return "EAP-Payload";
	case TEAPV2_TLV_INTERMEDIATE_RESULT:
		return "Intermediate-Result";
	case TEAPV2_TLV_CRYPTO_BINDING:
		return "Crypto-Binding";
	case TEAPV2_TLV_BASIC_PASSWORD_AUTH_REQ:
		return "Basic-Password-Auth-Req";
	case TEAPV2_TLV_BASIC_PASSWORD_AUTH_RESP:
		return "Basic-Password-Auth-Resp";
	case TEAPV2_TLV_PKCS7:
		return "PKCS#7";
	case TEAPV2_TLV_PKCS10:
		return "PKCS#10";
	case TEAPV2_TLV_TRUSTED_SERVER_ROOT:
		return "Trusted-Server-Root";
	case TEAPV2_TLV_CSR_ATTRS:
		return "CSR-Attributes";
	}

	return "?";
}


struct wpabuf * eap_teapv2_tlv_result(int status, int intermediate)
{
	struct wpabuf *buf;
	struct teapv2_tlv_result *result;

	if (status != TEAPV2_STATUS_FAILURE && status != TEAPV2_STATUS_SUCCESS)
		return NULL;

	buf = wpabuf_alloc(sizeof(*result));
	if (!buf)
		return NULL;
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Add %sResult TLV(status=%s)",
		   intermediate ? "Intermediate-" : "",
		   status == TEAPV2_STATUS_SUCCESS ? "Success" : "Failure");
	result = wpabuf_put(buf, sizeof(*result));
	result->tlv_type = host_to_be16(TEAPV2_TLV_MANDATORY |
					(intermediate ?
					 TEAPV2_TLV_INTERMEDIATE_RESULT :
					 TEAPV2_TLV_RESULT));
	result->length = host_to_be16(2);
	result->status = host_to_be16(status);
	return buf;
}


struct wpabuf * eap_teapv2_tlv_error(enum teapv2_error_codes error)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(4 + 4);
	if (!buf)
		return NULL;
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Add Error TLV(Error Code=%d)",
		   error);
	wpabuf_put_be16(buf, TEAPV2_TLV_MANDATORY | TEAPV2_TLV_ERROR);
	wpabuf_put_be16(buf, 4);
	wpabuf_put_be32(buf, error);
	return buf;
}


struct wpabuf * eap_teapv2_tlv_identity_type(enum teapv2_identity_types id)
{
	struct wpabuf *buf;

	buf = wpabuf_alloc(4 + 2);
	if (!buf)
		return NULL;
	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Add Identity-Type TLV(Identity-Type=%d)", id);
	wpabuf_put_be16(buf, TEAPV2_TLV_IDENTITY_TYPE);
	wpabuf_put_be16(buf, 2);
	wpabuf_put_be16(buf, id);
	return buf;
}
