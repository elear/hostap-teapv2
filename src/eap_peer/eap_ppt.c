/*
 * EAP peer method: EAP-PPT (EAP using Privacy Pass Token)
 * draft-ietf-emu-eap-ppt
 *
 * Copyright (c) 2024, The hostap Project
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * EAP-PPT MUST run inside a server-authenticated TLS tunnel
 * (TEAP, TTLS, PEAP, EAP-FAST). The peer authenticates by presenting
 * a Privacy Pass token (RFC 9577/9578); all payloads are JSON.
 *
 * Token storage: configure wpa_supplicant with:
 *   password="<base64url-encoded Privacy Pass token>"
 *
 * Key material is derived via the outer TLS exporter per spec Section 6.6.
 * In this implementation, getKey() derives material using HMAC-SHA256 of
 * the token with the EAP-PPT exporter label as a stub; correct derivation
 * requires the outer tunnel method to call tls_connection_export_key with
 * label EAP_PPT_TLS_EXPORTER_LABEL and context (Type || token).
 */

#include "includes.h"

#include "common.h"
#include "crypto/crypto.h"
#include "crypto/sha256.h"
#include "utils/base64.h"
#include "eap_i.h"
#include "eap_common/eap_ppt_common.h"

/* -------------------------------------------------------------------------
 * State machine
 * ------------------------------------------------------------------------- */

enum eap_ppt_state {
	PPT_INIT,
	PPT_CHALLENGE_RCVD,
	PPT_RESPONSE_SENT,
	PPT_DONE
};

struct eap_ppt_data {
	enum eap_ppt_state state;
	bool success;

	/* Base64url-encoded token from config (password field) */
	u8 *token_b64;
	size_t token_b64_len;

	/* Raw token bytes (decoded from token_b64) */
	u8 *token;
	size_t token_len;

	/* Derived key material (128 bytes: MSK || EMSK) */
	u8 key_material[EAP_PPT_KEY_MATERIAL_LEN];
	bool key_derived;
};

/* -------------------------------------------------------------------------
 * Minimal JSON helpers
 * These cover the narrow EAP-PPT JSON schema only.
 * ------------------------------------------------------------------------- */

/*
 * Find the first occurrence of a JSON string value for the given key.
 * Returns a malloc'd copy of the value, or NULL on failure.
 * Only handles top-level string values (not nested objects).
 */
static char * json_get_string(const char *json, const char *key)
{
	char search[128];
	const char *p, *start, *end;
	size_t vlen;

	if (!json || !key)
		return NULL;

	/* Build: "key": */
	snprintf(search, sizeof(search), "\"%s\"", key);
	p = os_strstr(json, search);
	if (!p)
		return NULL;

	p += os_strlen(search);

	/* Skip whitespace and colon */
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;
	if (*p != ':')
		return NULL;
	p++;
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;

	if (*p != '"')
		return NULL;
	p++; /* skip opening quote */

	start = p;
	/* Find closing quote (no escape handling needed for base64url tokens) */
	end = os_strchr(start, '"');
	if (!end)
		return NULL;

	vlen = end - start;
	return dup_binstr(start, vlen);
}

/*
 * Find the integer value for the given key.
 * Returns -1 on failure.
 */
static int json_get_int(const char *json, const char *key)
{
	char search[128];
	const char *p;

	if (!json || !key)
		return -1;

	snprintf(search, sizeof(search), "\"%s\"", key);
	p = os_strstr(json, search);
	if (!p)
		return -1;

	p += os_strlen(search);
	while (*p == ' ' || *p == ':' || *p == ' ' || *p == '\t')
		p++;

	if (*p < '0' || *p > '9')
		return -1;

	return atoi(p);
}

/*
 * Find the first string value within a JSON array for the given array key.
 * This is used to grab the first "challenge" value from the challenges array.
 * Returns malloc'd first array element string or NULL.
 */
static char * json_get_first_array_object(const char *json, const char *key)
{
	char search[128];
	const char *p, *obj_start, *obj_end;
	size_t vlen;

	if (!json || !key)
		return NULL;

	snprintf(search, sizeof(search), "\"%s\"", key);
	p = os_strstr(json, search);
	if (!p)
		return NULL;

	p += os_strlen(search);
	while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\r' || *p == '\n')
		p++;

	if (*p != '[')
		return NULL;
	p++; /* skip '[' */
	while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
		p++;

	if (*p == '"') {
		/* Array of strings */
		p++;
		obj_start = p;
		obj_end = os_strchr(obj_start, '"');
		if (!obj_end)
			return NULL;
		vlen = obj_end - obj_start;
		return dup_binstr(obj_start, vlen);
	}

	if (*p == '{') {
		/* Array of objects — return the full first object */
		int depth = 0;
		obj_start = p;
		do {
			if (*p == '{')
				depth++;
			else if (*p == '}')
				depth--;
			p++;
		} while (*p && depth > 0);
		obj_end = p;
		vlen = obj_end - obj_start;
		return dup_binstr(obj_start, vlen);
	}

	return NULL;
}

/* -------------------------------------------------------------------------
 * Base64url utilities
 * ------------------------------------------------------------------------- */

/* Add base64url padding if needed and return standard base64 string (malloc'd) */
static char * b64url_to_b64(const char *b64url, size_t len)
{
	size_t pad = (4 - (len % 4)) % 4;
	char *b64 = os_malloc(len + pad + 1);
	size_t i;

	if (!b64)
		return NULL;

	for (i = 0; i < len; i++) {
		char c = b64url[i];
		if (c == '-')
			b64[i] = '+';
		else if (c == '_')
			b64[i] = '/';
		else
			b64[i] = c;
	}
	for (i = 0; i < pad; i++)
		b64[len + i] = '=';
	b64[len + pad] = '\0';
	return b64;
}

/* Decode base64url string. Caller must os_free result. */
static u8 * b64url_decode(const char *str, size_t str_len, size_t *out_len)
{
	char *b64;
	u8 *out;

	b64 = b64url_to_b64(str, str_len);
	if (!b64)
		return NULL;

	out = base64_decode(b64, os_strlen(b64), out_len);
	os_free(b64);
	return out;
}


/* -------------------------------------------------------------------------
 * Key derivation
 *
 * Per spec Section 6.6:
 *   Context = Type(0x39) || token_bytes
 *   Key_Material = TLS_Exporter("EXPORTER_EAP_PPT_Key_Material", Context, 128)
 *   MSK  = Key_Material[0..63]
 *   EMSK = Key_Material[64..127]
 *
 * Because the outer TLS connection handle is not accessible from within an
 * inner EAP method, this implementation derives key material using
 * HMAC-SHA256 over the token with the exporter label as context. The outer
 * tunnel method should override this by calling tls_connection_export_key
 * with the appropriate context.
 * ------------------------------------------------------------------------- */

static int eap_ppt_derive_keys(struct eap_ppt_data *data)
{
	const char *label = EAP_PPT_TLS_EXPORTER_LABEL;
	u8 type_byte = EAP_TYPE_PPT_VAL;
	u8 context[1 + 512]; /* type || token, token ≤ 512 bytes */
	size_t ctx_len;
	u8 tmp[32];

	if (!data->token || data->token_len == 0)
		return -1;

	if (data->token_len > sizeof(context) - 1) {
		wpa_printf(MSG_WARNING, "EAP-PPT: Token too long for key context");
		return -1;
	}

	context[0] = type_byte;
	os_memcpy(context + 1, data->token, data->token_len);
	ctx_len = 1 + data->token_len;

	/*
	 * Stub derivation: two rounds of HMAC-SHA256 keyed on the label
	 * over the context. The outer tunnel should replace this by calling
	 * tls_connection_export_key(sm->ssl_ctx, outer_conn,
	 *   "EXPORTER_EAP_PPT_Key_Material", context, ctx_len, key_material, 128)
	 */
	if (hmac_sha256((const u8 *) label, os_strlen(label),
			context, ctx_len, tmp) < 0)
		return -1;

	/* MSK: expand to 64 bytes using two HMAC rounds with counter prefix */
	u8 ctr0[33], ctr1[33];
	ctr0[0] = 0x00;
	os_memcpy(ctr0 + 1, tmp, 32);
	ctr1[0] = 0x01;
	os_memcpy(ctr1 + 1, tmp, 32);

	if (hmac_sha256((const u8 *) label, os_strlen(label),
			ctr0, sizeof(ctr0),
			data->key_material) < 0 ||
	    hmac_sha256((const u8 *) label, os_strlen(label),
			ctr1, sizeof(ctr1),
			data->key_material + 32) < 0)
		return -1;

	/* EMSK: expand to 64 bytes using two more rounds */
	u8 ctr2[33], ctr3[33];
	ctr2[0] = 0x02;
	os_memcpy(ctr2 + 1, tmp, 32);
	ctr3[0] = 0x03;
	os_memcpy(ctr3 + 1, tmp, 32);

	if (hmac_sha256((const u8 *) label, os_strlen(label),
			ctr2, sizeof(ctr2),
			data->key_material + 64) < 0 ||
	    hmac_sha256((const u8 *) label, os_strlen(label),
			ctr3, sizeof(ctr3),
			data->key_material + 96) < 0)
		return -1;

	data->key_derived = true;
	return 0;
}

/* -------------------------------------------------------------------------
 * EAP method lifecycle
 * ------------------------------------------------------------------------- */

static void eap_ppt_deinit(struct eap_sm *sm, void *priv);

static void * eap_ppt_init(struct eap_sm *sm)
{
	struct eap_ppt_data *data;
	const u8 *password;
	size_t password_len;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->state = PPT_INIT;

	/*
	 * The Privacy Pass token is stored as the password field in
	 * wpa_supplicant.conf, base64url-encoded.
	 */
	password = eap_get_config_password(sm, &password_len);
	if (!password || password_len == 0) {
		wpa_printf(MSG_INFO, "EAP-PPT: No token configured "
			   "(set password to base64url-encoded Privacy Pass token)");
		/* Continue without token — will respond with empty token */
	} else {
		data->token_b64 = os_memdup(password, password_len);
		if (!data->token_b64) {
			eap_ppt_deinit(sm, data);
			return NULL;
		}
		data->token_b64_len = password_len;

		/* Decode token now so it is ready for key derivation */
		data->token = b64url_decode((const char *) data->token_b64,
					    data->token_b64_len,
					    &data->token_len);
		if (!data->token) {
			wpa_printf(MSG_WARNING, "EAP-PPT: Failed to decode "
				   "base64url token");
		}
	}

	wpa_printf(MSG_DEBUG, "EAP-PPT: Peer initialized, token %s",
		   data->token ? "loaded" : "absent");
	return data;
}

static void eap_ppt_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_ppt_data *data = priv;

	if (!data)
		return;

	os_free(data->token_b64);
	if (data->token) {
		os_memset(data->token, 0, data->token_len);
		os_free(data->token);
	}
	os_memset(data->key_material, 0, sizeof(data->key_material));
	os_free(data);
}

/* -------------------------------------------------------------------------
 * Request handlers
 * ------------------------------------------------------------------------- */

/*
 * Handle Subtype 1 (Challenge).
 * The server sends a JSON object with a "challenges" array; each element
 * is a base64url-encoded TokenChallenge structure. We pick the first one
 * (or the one matching our token type) and respond with our token.
 */
static struct wpabuf *
eap_ppt_process_challenge(struct eap_ppt_data *data,
			   struct eap_method_ret *ret, u8 id,
			   const u8 *payload, size_t payload_len)
{
	char *json = NULL;
	char *challenge = NULL;
	char *token_str = NULL;
	struct wpabuf *resp = NULL;
	char *b64_body;
	size_t b64_body_len;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Processing Challenge (Subtype 1)");
	wpa_hexdump_ascii(MSG_MSGDUMP, "EAP-PPT: Challenge payload",
			  payload, payload_len);

	json = dup_binstr(payload, payload_len);
	if (!json) {
		ret->ignore = true;
		return NULL;
	}

	/* Extract first challenge from the challenges array */
	challenge = json_get_first_array_object(json, EAP_PPT_JSON_CHALLENGES);
	if (!challenge) {
		wpa_printf(MSG_INFO, "EAP-PPT: No challenges array in request");
		/* Respond with empty token per spec */
	}

	/* Build the token to send */
	if (data->token_b64 && data->token_b64_len > 0) {
		/*
		 * Use the configured token directly (already base64url encoded).
		 * A production implementation would match challenge.token_type
		 * and challenge.issuer_name against stored tokens.
		 */
		token_str = dup_binstr((const char *) data->token_b64,
				       data->token_b64_len);
	}

	if (!token_str)
		token_str = os_strdup(""); /* empty token = no matching token */

	if (!token_str) {
		ret->ignore = true;
		goto done;
	}

	/* Derive key material from the token */
	if (data->token && data->token_len > 0) {
		if (eap_ppt_derive_keys(data) < 0)
			wpa_printf(MSG_WARNING, "EAP-PPT: Key derivation failed");
	}

	/*
	 * Build JSON response: {"token":"<base64url>"}
	 * Optionally include "extensions":[] if token has extensions.
	 */
	b64_body_len = 12 + os_strlen(token_str) + 2; /* {"token":"..."} */
	b64_body = os_zalloc(b64_body_len + 64);
	if (!b64_body) {
		ret->ignore = true;
		goto done;
	}
	snprintf(b64_body, b64_body_len + 64,
		 "{\"" EAP_PPT_JSON_TOKEN "\":\"%s\"}", token_str);

	/* Allocate EAP-Response: EAP header + Type + Subtype + JSON */
	resp = eap_msg_alloc(EAP_VENDOR_IETF, (enum eap_type) EAP_TYPE_PPT_VAL,
			     1 + os_strlen(b64_body),
			     EAP_CODE_RESPONSE, id);
	if (!resp) {
		os_free(b64_body);
		goto done;
	}

	/* Subtype byte */
	wpabuf_put_u8(resp, EAP_PPT_SUBTYPE_CHALLENGE);
	/* JSON payload */
	wpabuf_put_data(resp, b64_body, os_strlen(b64_body));
	os_free(b64_body);

	data->state = PPT_RESPONSE_SENT;
	ret->ignore = false;
	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_COND_SUCC;
	ret->allowNotifications = false;

done:
	os_free(json);
	os_free(challenge);
	os_free(token_str);
	return resp;
}

/*
 * Handle Subtype 2 (Error).
 * Log the error code and description, then send an empty Error response.
 */
static struct wpabuf *
eap_ppt_process_error(struct eap_ppt_data *data,
		      struct eap_method_ret *ret, u8 id,
		      const u8 *payload, size_t payload_len)
{
	char *json;
	int code;
	char *desc;
	struct wpabuf *resp;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Processing Error (Subtype 2)");

	json = dup_binstr(payload, payload_len);
	if (json) {
		code = json_get_int(json, EAP_PPT_JSON_CODE);
		desc = json_get_string(json, EAP_PPT_JSON_DESCRIPTION);
		wpa_printf(MSG_INFO, "EAP-PPT: Server error code %d%s%s",
			   code,
			   desc ? ": " : "",
			   desc ? desc : "");
		os_free(desc);
		os_free(json);
	}

	/* Send empty Error response */
	resp = eap_msg_alloc(EAP_VENDOR_IETF, (enum eap_type) EAP_TYPE_PPT_VAL,
			     1, EAP_CODE_RESPONSE, id);
	if (!resp) {
		ret->ignore = true;
		return NULL;
	}
	wpabuf_put_u8(resp, EAP_PPT_SUBTYPE_ERROR);

	data->state = PPT_DONE;
	data->success = false;
	ret->ignore = false;
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_FAIL;
	ret->allowNotifications = false;
	return resp;
}

/*
 * Handle Subtype 3 (Channel-Binding).
 * For the initial implementation, respond with an empty body.
 * A full implementation would include NAS-Identifier, Called-Station-Id, etc.
 */
static struct wpabuf *
eap_ppt_process_channel_binding(struct eap_ppt_data *data,
				struct eap_method_ret *ret, u8 id,
				const u8 *payload, size_t payload_len)
{
	struct wpabuf *resp;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Processing Channel-Binding (Subtype 3)");

	resp = eap_msg_alloc(EAP_VENDOR_IETF, (enum eap_type) EAP_TYPE_PPT_VAL,
			     1, EAP_CODE_RESPONSE, id);
	if (!resp) {
		ret->ignore = true;
		return NULL;
	}
	wpabuf_put_u8(resp, EAP_PPT_SUBTYPE_CHANNEL_BINDING);

	ret->ignore = false;
	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_COND_SUCC;
	ret->allowNotifications = false;
	return resp;
}

/* -------------------------------------------------------------------------
 * Main process dispatch
 * ------------------------------------------------------------------------- */

static struct wpabuf *
eap_ppt_process(struct eap_sm *sm, void *priv,
		struct eap_method_ret *ret,
		const struct wpabuf *reqData)
{
	struct eap_ppt_data *data = priv;
	const u8 *pos;
	size_t len;
	u8 subtype;
	u8 id;

	pos = eap_hdr_validate(EAP_VENDOR_IETF,
			       (enum eap_type) EAP_TYPE_PPT_VAL,
			       reqData, &len);
	if (!pos || len < 1) {
		wpa_printf(MSG_INFO, "EAP-PPT: Invalid message (too short)");
		ret->ignore = true;
		return NULL;
	}

	id = eap_get_id(reqData);
	subtype = *pos;
	pos++;
	len--;

	wpa_printf(MSG_DEBUG, "EAP-PPT: Received subtype %u, payload %zu bytes",
		   subtype, len);

	switch (subtype) {
	case EAP_PPT_SUBTYPE_CHALLENGE:
		data->state = PPT_CHALLENGE_RCVD;
		return eap_ppt_process_challenge(data, ret, id, pos, len);

	case EAP_PPT_SUBTYPE_ERROR:
		return eap_ppt_process_error(data, ret, id, pos, len);

	case EAP_PPT_SUBTYPE_CHANNEL_BINDING:
		return eap_ppt_process_channel_binding(data, ret, id, pos, len);

	default:
		wpa_printf(MSG_INFO, "EAP-PPT: Unknown subtype %u — ignoring",
			   subtype);
		ret->ignore = true;
		return NULL;
	}
}

/* -------------------------------------------------------------------------
 * Key export
 * ------------------------------------------------------------------------- */

static bool eap_ppt_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_ppt_data *data = priv;
	return data->key_derived && data->success;
}

static u8 * eap_ppt_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_ppt_data *data = priv;
	u8 *key;

	if (!data->key_derived || !data->success)
		return NULL;

	key = os_memdup(data->key_material, EAP_PPT_MSK_LEN);
	if (!key)
		return NULL;
	*len = EAP_PPT_MSK_LEN;
	return key;
}

static u8 * eap_ppt_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_ppt_data *data = priv;
	u8 *key;

	if (!data->key_derived || !data->success)
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

int eap_peer_ppt_register(void)
{
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF,
				    (enum eap_type) EAP_TYPE_PPT_VAL,
				    "PPT");
	if (!eap)
		return -1;

	eap->init = eap_ppt_init;
	eap->deinit = eap_ppt_deinit;
	eap->process = eap_ppt_process;
	eap->isKeyAvailable = eap_ppt_isKeyAvailable;
	eap->getKey = eap_ppt_getKey;
	eap->get_emsk = eap_ppt_get_emsk;

	return eap_peer_method_register(eap);
}
