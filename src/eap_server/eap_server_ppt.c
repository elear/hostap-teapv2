/*
 * hostapd / EAP-PPT (EAP using Privacy Pass Token) server
 * draft-ietf-emu-eap-ppt
 *
 * Copyright (c) 2024, The hostap Project
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * EAP-PPT MUST run inside a server-authenticated TLS tunnel.
 * The server builds a Privacy Pass TokenChallenge per RFC 9577 §2.1,
 * sends it in a JSON "challenges" array, and verifies the returned token.
 *
 * Configuration (hostapd.conf):
 *   eap_ppt_issuer_name=<DNS name of token issuer>   (default: issuer.example)
 *   eap_ppt_origin_info=<origin name>                (default: empty)
 *   eap_ppt_token_type=<1|2>                         (default: 2 = Blind RSA)
 *
 * Token verification in this initial implementation is a stub that accepts
 * any non-empty token.  A production implementation must verify the token
 * cryptographically against the issuer public key (Type 2: RSABSSA) or via
 * an external redemption service.
 */

#include "includes.h"

#include "common.h"
#include "crypto/crypto.h"
#include "crypto/random.h"
#include "crypto/sha256.h"
#include "utils/base64.h"
#include "eap_server/eap_i.h"
#include "eap_common/eap_ppt_common.h"

/* -------------------------------------------------------------------------
 * TokenChallenge structure constants (RFC 9577 §2.1)
 *   token_type        2 bytes (big-endian)
 *   issuer_name       2-byte-len || bytes
 *   redemption_ctx    1-byte-len || 0 or 32 bytes
 *   origin_info       2-byte-len || bytes
 * ------------------------------------------------------------------------- */
#define PPT_NONCE_LEN 32

/* -------------------------------------------------------------------------
 * State machine
 * ------------------------------------------------------------------------- */
enum eap_ppt_server_state {
	PPT_CHALLENGE,
	PPT_SUCCESS,
	PPT_FAILURE
};

struct eap_ppt_server_data {
	enum eap_ppt_server_state state;

	/* Server configuration */
	char *issuer_name;   /* e.g. "issuer.example" */
	char *origin_info;   /* e.g. "network.example" or "" */
	u16  token_type;     /* 1=VOPRF, 2=Blind RSA */

	/* Nonce for the current challenge */
	u8 nonce[PPT_NONCE_LEN];

	/* Token received from peer (raw bytes) */
	u8 *peer_token;
	size_t peer_token_len;

	/* Derived key material (128 bytes: MSK || EMSK) */
	u8 key_material[EAP_PPT_KEY_MATERIAL_LEN];
	bool key_derived;
};

/* -------------------------------------------------------------------------
 * Minimal JSON helpers (same design as peer side)
 * ------------------------------------------------------------------------- */

static char * srv_json_get_string(const char *json, const char *key)
{
	char search[128];
	const char *p, *start, *end;
	size_t vlen;

	if (!json || !key)
		return NULL;

	snprintf(search, sizeof(search), "\"%s\"", key);
	p = os_strstr(json, search);
	if (!p)
		return NULL;

	p += os_strlen(search);
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	if (*p != ':')
		return NULL;
	p++;
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	if (*p != '"')
		return NULL;
	p++;

	start = p;
	end = os_strchr(start, '"');
	if (!end)
		return NULL;

	vlen = end - start;
	return dup_binstr(start, vlen);
}

/* -------------------------------------------------------------------------
 * Base64url helpers
 * ------------------------------------------------------------------------- */

static char * srv_b64url_to_b64(const char *in, size_t in_len)
{
	size_t pad = (4 - (in_len % 4)) % 4;
	char *out = os_malloc(in_len + pad + 1);
	size_t i;

	if (!out)
		return NULL;

	for (i = 0; i < in_len; i++) {
		char c = in[i];
		if (c == '-')      out[i] = '+';
		else if (c == '_') out[i] = '/';
		else               out[i] = c;
	}
	for (i = 0; i < pad; i++)
		out[in_len + i] = '=';
	out[in_len + pad] = '\0';
	return out;
}

static u8 * srv_b64url_decode(const char *str, size_t str_len, size_t *out_len)
{
	char *b64;
	u8 *out;

	b64 = srv_b64url_to_b64(str, str_len);
	if (!b64)
		return NULL;

	out = base64_decode(b64, os_strlen(b64), out_len);
	os_free(b64);
	return out;
}

static char * srv_b64url_encode(const u8 *data, size_t len)
{
	char *b64;
	size_t b64_len;
	char *out;
	size_t i, j = 0;

	b64 = (char *) base64_encode(data, len, &b64_len);
	if (!b64)
		return NULL;

	out = os_malloc(b64_len + 1);
	if (!out) {
		os_free(b64);
		return NULL;
	}

	for (i = 0; i < b64_len; i++) {
		char c = b64[i];
		if (c == '\n') continue;
		if (c == '+')      out[j++] = '-';
		else if (c == '/') out[j++] = '_';
		else if (c == '=') continue;
		else               out[j++] = c;
	}
	out[j] = '\0';
	os_free(b64);
	return out;
}

/* -------------------------------------------------------------------------
 * TokenChallenge encoding (RFC 9577 §2.1)
 *
 *   struct {
 *       uint16 token_type;
 *       opaque issuer_name<1..2^16-1>;   // length-prefixed
 *       opaque redemption_context<0..32>; // 1-byte length prefix
 *       opaque origin_info<0..2^16-1>;   // length-prefixed
 *   } TokenChallenge;
 * ------------------------------------------------------------------------- */
static u8 * build_token_challenge(u16 token_type,
				  const char *issuer_name,
				  const u8 *nonce, size_t nonce_len,
				  const char *origin_info,
				  size_t *out_len)
{
	size_t issuer_len = issuer_name ? os_strlen(issuer_name) : 0;
	size_t origin_len = origin_info ? os_strlen(origin_info) : 0;
	/* 2 + 2 + issuer + 1 + nonce + 2 + origin */
	size_t total = 2 + 2 + issuer_len + 1 + nonce_len + 2 + origin_len;
	u8 *buf, *p;

	buf = os_malloc(total);
	if (!buf)
		return NULL;

	p = buf;

	/* token_type (big-endian) */
	WPA_PUT_BE16(p, token_type);
	p += 2;

	/* issuer_name */
	WPA_PUT_BE16(p, (u16) issuer_len);
	p += 2;
	if (issuer_len) {
		os_memcpy(p, issuer_name, issuer_len);
		p += issuer_len;
	}

	/* redemption_context: 1-byte length + nonce bytes */
	*p++ = (u8) nonce_len;
	if (nonce_len) {
		os_memcpy(p, nonce, nonce_len);
		p += nonce_len;
	}

	/* origin_info */
	WPA_PUT_BE16(p, (u16) origin_len);
	p += 2;
	if (origin_len) {
		os_memcpy(p, origin_info, origin_len);
		p += origin_len;
	}

	*out_len = p - buf;
	return buf;
}

/* -------------------------------------------------------------------------
 * Token verification (stub)
 *
 * A production implementation must:
 *   Type 2 (Blind RSA): parse the token struct per RFC 9577 §2.2 and verify
 *     the RSA-Blind-Signature using the issuer's public key (RFC 9474).
 *   Type 1 (VOPRF): verify via VOPRF finalize step (RFC 9497).
 *   Both: redeem nonce (check and persist against double-spend set).
 * ------------------------------------------------------------------------- */
static bool verify_token(struct eap_ppt_server_data *data,
			 const u8 *token, size_t token_len)
{
	if (!token || token_len == 0) {
		wpa_printf(MSG_INFO, "EAP-PPT: Empty token — rejecting");
		return false;
	}

	/*
	 * Stub: accept any non-empty token.
	 * TODO: implement cryptographic verification per RFC 9577/9578.
	 */
	wpa_printf(MSG_DEBUG, "EAP-PPT: Token accepted (stub verification, "
		   "len=%zu)", token_len);
	return true;
}

/* -------------------------------------------------------------------------
 * Key derivation (server side, mirrors peer)
 * ------------------------------------------------------------------------- */
static int eap_ppt_server_derive_keys(struct eap_ppt_server_data *data)
{
	const char *label = EAP_PPT_TLS_EXPORTER_LABEL;
	u8 type_byte = EAP_TYPE_PPT_VAL;
	u8 context[1 + 512];
	size_t ctx_len;
	u8 tmp[32];
	u8 ctr[33];

	if (!data->peer_token || data->peer_token_len == 0)
		return -1;

	if (data->peer_token_len > sizeof(context) - 1)
		return -1;

	context[0] = type_byte;
	os_memcpy(context + 1, data->peer_token, data->peer_token_len);
	ctx_len = 1 + data->peer_token_len;

	if (hmac_sha256((const u8 *) label, os_strlen(label),
			context, ctx_len, tmp) < 0)
		return -1;

	/* Derive 128 bytes: four HMAC-SHA256 rounds (32 bytes each) */
	int i;
	for (i = 0; i < 4; i++) {
		ctr[0] = (u8) i;
		os_memcpy(ctr + 1, tmp, 32);
		if (hmac_sha256((const u8 *) label, os_strlen(label),
				ctr, sizeof(ctr),
				data->key_material + i * 32) < 0)
			return -1;
	}

	data->key_derived = true;
	return 0;
}

/* -------------------------------------------------------------------------
 * EAP method lifecycle
 * ------------------------------------------------------------------------- */

static void eap_ppt_server_reset(struct eap_sm *sm, void *priv);

static void * eap_ppt_server_init(struct eap_sm *sm)
{
	struct eap_ppt_server_data *data;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->state = PPT_CHALLENGE;
	data->token_type = EAP_PPT_TOKEN_TYPE_BLIND_RSA; /* default Type 2 */

	/*
	 * Use hardcoded defaults; a production implementation would read
	 * from hapd->conf->eap_ppt_issuer_name etc.
	 */
	data->issuer_name = os_strdup("issuer.example");
	data->origin_info = os_strdup("");

	if (!data->issuer_name || !data->origin_info) {
		eap_ppt_server_reset(sm, data);
		return NULL;
	}

	/* Generate a fresh nonce for this session */
	if (random_get_bytes(data->nonce, PPT_NONCE_LEN) < 0) {
		wpa_printf(MSG_ERROR, "EAP-PPT: Failed to generate nonce");
		eap_ppt_server_reset(sm, data);
		return NULL;
	}

	wpa_printf(MSG_DEBUG, "EAP-PPT: Server initialized, issuer=%s",
		   data->issuer_name);
	return data;
}

static void eap_ppt_server_reset(struct eap_sm *sm, void *priv)
{
	struct eap_ppt_server_data *data = priv;

	if (!data)
		return;

	os_free(data->issuer_name);
	os_free(data->origin_info);
	if (data->peer_token) {
		os_memset(data->peer_token, 0, data->peer_token_len);
		os_free(data->peer_token);
	}
	os_memset(data->key_material, 0, sizeof(data->key_material));
	bin_clear_free(data, sizeof(*data));
}

/* -------------------------------------------------------------------------
 * buildReq: produce the EAP-Request for the current state
 * ------------------------------------------------------------------------- */

static struct wpabuf *
eap_ppt_build_challenge(struct eap_sm *sm,
			struct eap_ppt_server_data *data, u8 id)
{
	u8 *challenge_bytes = NULL;
	size_t challenge_len;
	char *challenge_b64 = NULL;
	char *json = NULL;
	size_t json_len;
	struct wpabuf *req = NULL;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Building Challenge (Subtype 1)");

	/* Build binary TokenChallenge structure */
	challenge_bytes = build_token_challenge(data->token_type,
						data->issuer_name,
						data->nonce, PPT_NONCE_LEN,
						data->origin_info,
						&challenge_len);
	if (!challenge_bytes) {
		wpa_printf(MSG_ERROR, "EAP-PPT: Failed to build TokenChallenge");
		goto fail;
	}

	/* Base64url-encode the TokenChallenge */
	challenge_b64 = srv_b64url_encode(challenge_bytes, challenge_len);
	os_free(challenge_bytes);
	challenge_bytes = NULL;
	if (!challenge_b64) {
		wpa_printf(MSG_ERROR, "EAP-PPT: Failed to encode challenge");
		goto fail;
	}

	/*
	 * Build JSON: {"challenges":["<base64url>"],"token-key":""}
	 * token-key would contain the issuer's public key in a production
	 * implementation; an empty string is sent here.
	 */
	json_len = 32 + os_strlen(challenge_b64) + 1;
	json = os_zalloc(json_len + 32);
	if (!json)
		goto fail;

	snprintf(json, json_len + 32,
		 "{\"" EAP_PPT_JSON_CHALLENGES "\":[\"%s\"],"
		 "\"" EAP_PPT_JSON_TOKEN_KEY "\":\"\"}",
		 challenge_b64);

	wpa_printf(MSG_MSGDUMP, "EAP-PPT: Challenge JSON: %s", json);

	/* Allocate EAP-Request: Type + Subtype + JSON */
	req = eap_msg_alloc(EAP_VENDOR_IETF, (enum eap_type) EAP_TYPE_PPT_VAL,
			    1 + os_strlen(json),
			    EAP_CODE_REQUEST, id);
	if (!req)
		goto fail;

	wpabuf_put_u8(req, EAP_PPT_SUBTYPE_CHALLENGE);
	wpabuf_put_data(req, json, os_strlen(json));

out:
	os_free(challenge_b64);
	os_free(json);
	return req;

fail:
	data->state = PPT_FAILURE;
	wpabuf_free(req);
	req = NULL;
	goto out;
}

static struct wpabuf * __attribute__((unused))
eap_ppt_build_error(struct eap_sm *sm,
		    struct eap_ppt_server_data *data, u8 id,
		    int code, const char *description)
{
	char json[256];
	struct wpabuf *req;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Sending Error (code=%d)", code);

	if (description && description[0]) {
		snprintf(json, sizeof(json),
			 "{\"" EAP_PPT_JSON_CODE "\":%d,"
			 "\"" EAP_PPT_JSON_DESCRIPTION "\":\"%s\"}",
			 code, description);
	} else {
		snprintf(json, sizeof(json),
			 "{\"" EAP_PPT_JSON_CODE "\":%d}", code);
	}

	req = eap_msg_alloc(EAP_VENDOR_IETF, (enum eap_type) EAP_TYPE_PPT_VAL,
			    1 + os_strlen(json),
			    EAP_CODE_REQUEST, id);
	if (!req) {
		data->state = PPT_FAILURE;
		return NULL;
	}

	wpabuf_put_u8(req, EAP_PPT_SUBTYPE_ERROR);
	wpabuf_put_data(req, json, os_strlen(json));
	return req;
}

static struct wpabuf *
eap_ppt_server_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_ppt_server_data *data = priv;

	switch (data->state) {
	case PPT_CHALLENGE:
		return eap_ppt_build_challenge(sm, data, id);
	default:
		wpa_printf(MSG_ERROR, "EAP-PPT: buildReq in unexpected state %d",
			   data->state);
		return NULL;
	}
}

/* -------------------------------------------------------------------------
 * check: validate that the response subtype matches what we expect
 * ------------------------------------------------------------------------- */

static bool eap_ppt_server_check(struct eap_sm *sm, void *priv,
				 struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;
	u8 subtype;

	pos = eap_hdr_validate(EAP_VENDOR_IETF,
			       (enum eap_type) EAP_TYPE_PPT_VAL,
			       respData, &len);
	if (!pos || len < 1) {
		wpa_printf(MSG_INFO, "EAP-PPT: Invalid response (too short)");
		return true; /* ignore */
	}

	subtype = *pos;

	/* We only expect Subtype 1 (Challenge response) in current state */
	if (subtype != EAP_PPT_SUBTYPE_CHALLENGE &&
	    subtype != EAP_PPT_SUBTYPE_ERROR &&
	    subtype != EAP_PPT_SUBTYPE_CHANNEL_BINDING) {
		wpa_printf(MSG_INFO, "EAP-PPT: Unknown subtype %u in response",
			   subtype);
		return true;
	}

	return false;
}

/* -------------------------------------------------------------------------
 * process: parse the peer's response and drive the state machine
 * ------------------------------------------------------------------------- */

static void eap_ppt_server_process(struct eap_sm *sm, void *priv,
				   struct wpabuf *respData)
{
	struct eap_ppt_server_data *data = priv;
	const u8 *pos;
	size_t len;
	u8 subtype;
	char *json = NULL;
	char *token_b64 = NULL;

	pos = eap_hdr_validate(EAP_VENDOR_IETF,
			       (enum eap_type) EAP_TYPE_PPT_VAL,
			       respData, &len);
	if (!pos || len < 1) {
		data->state = PPT_FAILURE;
		return;
	}

	subtype = *pos;
	pos++;
	len--;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Received response subtype %u "
		   "(%zu bytes payload)", subtype, len);

	switch (subtype) {
	case EAP_PPT_SUBTYPE_CHALLENGE:
		/* Parse token from JSON response */
		json = dup_binstr(pos, len);
		if (!json) {
			data->state = PPT_FAILURE;
			break;
		}

		token_b64 = srv_json_get_string(json, EAP_PPT_JSON_TOKEN);
		if (!token_b64 || token_b64[0] == '\0') {
			wpa_printf(MSG_INFO, "EAP-PPT: Peer returned empty token");
			data->state = PPT_FAILURE;
			break;
		}

		wpa_printf(MSG_DEBUG, "EAP-PPT: Received token (b64url len=%zu)",
			   os_strlen(token_b64));

		/* Decode the token */
		data->peer_token = srv_b64url_decode(token_b64,
						      os_strlen(token_b64),
						      &data->peer_token_len);
		if (!data->peer_token) {
			wpa_printf(MSG_INFO, "EAP-PPT: Failed to decode token");
			data->state = PPT_FAILURE;
			break;
		}

		wpa_hexdump_key(MSG_MSGDUMP, "EAP-PPT: Decoded peer token",
				data->peer_token, data->peer_token_len);

		/* Verify the token */
		if (!verify_token(data, data->peer_token, data->peer_token_len)) {
			wpa_printf(MSG_INFO, "EAP-PPT: Token verification failed");
			data->state = PPT_FAILURE;
			break;
		}

		/* Derive key material */
		if (eap_ppt_server_derive_keys(data) < 0) {
			wpa_printf(MSG_WARNING,
				   "EAP-PPT: Key derivation failed");
			/* Non-fatal for the authentication result */
		}

		wpa_printf(MSG_DEBUG, "EAP-PPT: Authentication successful");
		data->state = PPT_SUCCESS;
		break;

	case EAP_PPT_SUBTYPE_ERROR:
		wpa_printf(MSG_INFO, "EAP-PPT: Peer sent error response");
		data->state = PPT_FAILURE;
		break;

	case EAP_PPT_SUBTYPE_CHANNEL_BINDING:
		/*
		 * Channel-Binding response: validate and consider done.
		 * Stub: accept any CB response without validation.
		 */
		wpa_printf(MSG_DEBUG, "EAP-PPT: Channel-binding response "
			   "accepted (stub)");
		data->state = PPT_SUCCESS;
		break;

	default:
		wpa_printf(MSG_INFO, "EAP-PPT: Unexpected subtype %u", subtype);
		data->state = PPT_FAILURE;
		break;
	}

	os_free(json);
	os_free(token_b64);
}

/* -------------------------------------------------------------------------
 * State queries and key export
 * ------------------------------------------------------------------------- */

static bool eap_ppt_server_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_ppt_server_data *data = priv;
	return data->state == PPT_SUCCESS || data->state == PPT_FAILURE;
}

static bool eap_ppt_server_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_ppt_server_data *data = priv;
	return data->state == PPT_SUCCESS;
}

static u8 * eap_ppt_server_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_ppt_server_data *data = priv;
	u8 *key;

	if (data->state != PPT_SUCCESS || !data->key_derived)
		return NULL;

	key = os_memdup(data->key_material, EAP_PPT_MSK_LEN);
	if (!key)
		return NULL;

	*len = EAP_PPT_MSK_LEN;
	return key;
}

static u8 * eap_ppt_server_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_ppt_server_data *data = priv;
	u8 *key;

	if (data->state != PPT_SUCCESS || !data->key_derived)
		return NULL;

	key = os_memdup(data->key_material + EAP_PPT_MSK_LEN, EAP_PPT_EMSK_LEN);
	if (!key)
		return NULL;

	*len = EAP_PPT_EMSK_LEN;
	return key;
}

/* -------------------------------------------------------------------------
 * Registration
 * ------------------------------------------------------------------------- */

int eap_server_ppt_register(void)
{
	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF,
				      (enum eap_type) EAP_TYPE_PPT_VAL,
				      "PPT");
	if (!eap)
		return -1;

	eap->init = eap_ppt_server_init;
	eap->reset = eap_ppt_server_reset;
	eap->buildReq = eap_ppt_server_buildReq;
	eap->check = eap_ppt_server_check;
	eap->process = eap_ppt_server_process;
	eap->isDone = eap_ppt_server_isDone;
	eap->isSuccess = eap_ppt_server_isSuccess;
	eap->getKey = eap_ppt_server_getKey;
	eap->get_emsk = eap_ppt_server_get_emsk;

	return eap_server_method_register(eap);
}
