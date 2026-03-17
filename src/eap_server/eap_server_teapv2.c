/*
 * EAP-TEAPV2 server (RFC 7170)
 * Copyright (c) 2004-2024, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/tls.h"
#include "crypto/random.h"
#include "base64.h"
#include "tls/asn1.h"
#include "eap_common/eap_teapv2_common.h"
#include "eap_i.h"
#include "eap_tls_common.h"


static void eap_teapv2_reset(struct eap_sm *sm, void *priv);


struct eap_teapv2_data {
	struct eap_ssl_data ssl;
	enum {
		START, PHASE1, PHASE1B, PHASE2_START, PHASE2_ID,
		PHASE2_BASIC_AUTH, PHASE2_WAIT_PKCS10, PHASE2_METHOD,
		CRYPTO_BINDING, PKCS7_READY,
		FAILURE_SEND_RESULT, SUCCESS_SEND_RESULT, SUCCESS, FAILURE
	} state;

	u8 teapv2_version;
	u8 peer_version;
	u16 tls_cs;

	const struct eap_method *phase2_method;
	void *phase2_priv;

	u8 crypto_binding_nonce[32];
	int final_result;

	u8 simck[EAP_TEAPV2_SIMCK_LEN];
	u8 simck_msk[EAP_TEAPV2_SIMCK_LEN];
	u8 cmk_msk[EAP_TEAPV2_CMK_LEN];
	u8 simck_emsk[EAP_TEAPV2_SIMCK_LEN];
	u8 cmk_emsk[EAP_TEAPV2_CMK_LEN];
	int simck_idx;
	bool cmk_emsk_available;
	bool request_pkcs10;

	u8 *srv_id;
	size_t srv_id_len;
	char *srv_id_info;

	unsigned int basic_auth_not_done:1;
	unsigned int inner_eap_not_done:1;
	int skipped_inner_auth;
	bool inner_method_done;
	struct wpabuf *pending_phase2_resp;
	struct wpabuf *server_outer_tlvs;
	struct wpabuf *peer_outer_tlvs;
	u8 *identity; /* from client certificate */
	size_t identity_len;
	int eap_seq;
	int tnc_started;

	enum teapv2_error_codes error_code;
	enum teapv2_identity_types cur_id_type;
	bool cb_required;
	bool check_crypto_binding;
	struct wpabuf *pkcs7_cert;
	struct wpabuf *pkcs10_csr;
	bool pkcs10_expected;
	struct wpabuf *trusted_server_root;
	struct wpabuf *csr_attrs;
};


static int eap_teapv2_process_phase2_start(struct eap_sm *sm,
					 struct eap_teapv2_data *data);
static int eap_teapv2_phase2_init(struct eap_sm *sm, struct eap_teapv2_data *data,
				int vendor, enum eap_type eap_type);

static struct wpabuf *
eap_teapv2_load_trusted_server_root(const char *path)
{
	u8 *buf, *der;
	size_t len, der_len;
	char *pos, *end;
	struct wpabuf *cert;
	const char *pem_begin = "-----BEGIN CERTIFICATE-----";
	const char *pem_end = "-----END CERTIFICATE-----";

	buf = (u8 *) os_readfile(path, &len);
	if (!buf) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to read trusted server root '%s'",
			   path);
		return NULL;
	}

	pos = os_strstr((char *) buf, pem_begin);
	if (pos) {
		pos += os_strlen(pem_begin);
		end = os_strstr(pos, pem_end);
		if (!end) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: No PEM end tag in trusted server root '%s'",
				   path);
			os_free(buf);
			return NULL;
		}
		der = base64_decode(pos, end - pos, &der_len);
		os_free(buf);
		if (!der) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to decode PEM trusted server root '%s'",
				   path);
			return NULL;
		}
		cert = wpabuf_alloc_copy(der, der_len);
		os_free(der);
		return cert;
	}

	cert = wpabuf_alloc_copy(buf, len);
	os_free(buf);
	return cert;
}

static struct wpabuf * eap_teapv2_load_csr_attrs(const char *val)
{
	u8 *der;
	size_t der_len;
	struct wpabuf *attrs;
	struct asn1_hdr hdr;
	const u8 *end = NULL;

	if (!val || !*val)
		return NULL;

	der = base64_decode(val, os_strlen(val), &der_len);
	if (!der || !der_len) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to decode CSR Attributes (base64)");
		os_free(der);
		return NULL;
	}

	if (asn1_get_sequence(der, der_len, &hdr, &end) < 0 ||
	    end != der + der_len) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: CSR Attributes is not a DER SEQUENCE");
		os_free(der);
		return NULL;
	}

	attrs = wpabuf_alloc_copy(der, der_len);
	os_free(der);
	return attrs;
}

static bool eap_teapv2_cert_near_expiry(struct eap_sm *sm,
					struct eap_teapv2_data *data)
{
	struct os_time not_before, not_after, now;
	long long lifetime, remaining;

	if (!sm->cfg->eap_teapv2_request_action_pkcs10)
		return false;

	if (tls_connection_peer_cert_validity(sm->cfg->ssl_ctx, data->ssl.conn,
					      &not_before, &not_after) < 0)
		return false;

	if (os_get_time(&now) < 0)
		return false;

	lifetime = (long long) not_after.sec - (long long) not_before.sec;
	remaining = (long long) not_after.sec - (long long) now.sec;
	if (lifetime <= 0 || remaining < 0)
		return false;

	return remaining * 3 < lifetime * 2;
}

static bool eap_teapv2_cert_not_signed_by_pkcs7(struct eap_sm *sm,
						struct eap_teapv2_data *data)
{
	int res;

	if (!sm->cfg->eap_teapv2_request_action_pkcs10_untrusted)
		return false;
	if (!sm->cfg->teapv2_pkcs7_cert)
		return false;

	res = tls_connection_peer_cert_issued_by(sm->cfg->ssl_ctx,
						 data->ssl.conn,
						 sm->cfg->teapv2_pkcs7_cert);
	if (res < 0) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Could not determine peer certificate issuer");
		return false;
	}
	if (res == 0) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Peer certificate not signed by TEAPV2 PKCS#7 signing cert - request PKCS#10 CSR");
		return true;
	}
	return false;
}


static const char * eap_teapv2_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case PHASE1:
		return "PHASE1";
	case PHASE1B:
		return "PHASE1B";
	case PHASE2_START:
		return "PHASE2_START";
	case PHASE2_ID:
		return "PHASE2_ID";
	case PHASE2_BASIC_AUTH:
		return "PHASE2_BASIC_AUTH";
	case PHASE2_WAIT_PKCS10:
		return "PHASE2_WAIT_PKCS10";
	case PHASE2_METHOD:
		return "PHASE2_METHOD";
	case CRYPTO_BINDING:
		return "CRYPTO_BINDING";
	case PKCS7_READY:
		return "PKCS7_READY";
	case FAILURE_SEND_RESULT:
		return "FAILURE_SEND_RESULT";
	case SUCCESS_SEND_RESULT:
		return "SUCCESS_SEND_RESULT";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "Unknown?!";
	}
}


static void eap_teapv2_state(struct eap_teapv2_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: %s -> %s",
		   eap_teapv2_state_txt(data->state),
		   eap_teapv2_state_txt(state));
	data->state = state;
}


static enum eap_type eap_teapv2_req_failure(struct eap_teapv2_data *data,
					  enum teapv2_error_codes error)
{
	eap_teapv2_state(data, FAILURE_SEND_RESULT);
	return EAP_TYPE_NONE;
}


static int eap_teapv2_derive_key_auth(struct eap_sm *sm,
				    struct eap_teapv2_data *data)
{
	int res;

	/* RFC 7170, Section 5.1 */
	res = tls_connection_export_key(sm->cfg->ssl_ctx, data->ssl.conn,
					TEAPV2_TLS_EXPORTER_LABEL_SKS, NULL, 0,
					data->simck, EAP_TEAPV2_SIMCK_LEN);
	if (res)
		return res;
	wpa_hexdump_key(MSG_DEBUG,
			"EAP-TEAPV2: session_key_seed (S-IMCK[0])",
			data->simck, EAP_TEAPV2_SIMCK_LEN);
	os_memcpy(data->simck_msk, data->simck, EAP_TEAPV2_SIMCK_LEN);
	os_memcpy(data->simck_emsk, data->simck, EAP_TEAPV2_SIMCK_LEN);
	data->simck_idx = 0;
	return 0;
}


static int eap_teapv2_update_icmk(struct eap_sm *sm, struct eap_teapv2_data *data)
{
	u8 *msk = NULL, *emsk = NULL;
	size_t msk_len = 0, emsk_len = 0;
	int res;

	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Deriving ICMK[%d] (S-IMCK and CMK)",
		   data->simck_idx + 1);

	if (sm->cfg->eap_teapv2_auth == 1)
		goto out; /* no MSK derived in Basic-Password-Auth */

	if (!data->phase2_method || !data->phase2_priv) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: Phase 2 method not available");
		return -1;
	}

	if (data->phase2_method->getKey) {
		msk = data->phase2_method->getKey(sm, data->phase2_priv,
						  &msk_len);
		if (!msk) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Could not fetch Phase 2 MSK");
			return -1;
		}
	}

	if (data->phase2_method->get_emsk) {
		emsk = data->phase2_method->get_emsk(sm, data->phase2_priv,
						     &emsk_len);
	}

out:
	res = eap_teapv2_derive_imck(data->tls_cs, data->simck,
				   msk, msk_len, emsk, emsk_len,
				   data->simck_msk, data->cmk_msk,
				   data->simck_emsk, data->cmk_emsk);
	bin_clear_free(msk, msk_len);
	bin_clear_free(emsk, emsk_len);
	if (res == 0) {
		data->simck_idx++;
		data->cmk_emsk_available = emsk != NULL;
	}
	return 0;
}


static void * eap_teapv2_init(struct eap_sm *sm)
{
	struct eap_teapv2_data *data;
	unsigned int tls_flags;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;
	data->teapv2_version = EAP_TEAPV2_VERSION;
	data->state = START;

	tls_flags = sm->cfg->tls_flags;
	tls_flags |= TLS_CONN_DISABLE_TLSv1_0 | TLS_CONN_DISABLE_TLSv1_1 |
		TLS_CONN_DISABLE_TLSv1_2;
	tls_flags &= ~TLS_CONN_DISABLE_TLSv1_3;

	if (eap_server_tls_ssl_init_flags(
		    sm, &data->ssl, sm->cfg->eap_teapv2_auth == 2 ? 2 : 0,
		    EAP_TYPE_TEAPV2, tls_flags)) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: Failed to initialize SSL.");
		eap_teapv2_reset(sm, data);
		return NULL;
	}

	if (!sm->cfg->eap_fast_a_id) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: No A-ID configured");
		eap_teapv2_reset(sm, data);
		return NULL;
	}
	data->srv_id = os_malloc(sm->cfg->eap_fast_a_id_len);
	if (!data->srv_id) {
		eap_teapv2_reset(sm, data);
		return NULL;
	}
	os_memcpy(data->srv_id, sm->cfg->eap_fast_a_id,
		  sm->cfg->eap_fast_a_id_len);
	data->srv_id_len = sm->cfg->eap_fast_a_id_len;

	if (!sm->cfg->eap_fast_a_id_info) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: No A-ID-Info configured");
		eap_teapv2_reset(sm, data);
		return NULL;
	}
	data->srv_id_info = os_strdup(sm->cfg->eap_fast_a_id_info);
	if (!data->srv_id_info) {
		eap_teapv2_reset(sm, data);
		return NULL;
	}

	if (sm->cfg->eap_teapv2_trusted_server_root) {
		data->trusted_server_root =
			eap_teapv2_load_trusted_server_root(
				sm->cfg->eap_teapv2_trusted_server_root);
		if (!data->trusted_server_root) {
			eap_teapv2_reset(sm, data);
			return NULL;
		}
	}
	if (sm->cfg->eap_teapv2_csrattrs) {
		data->csr_attrs =
			eap_teapv2_load_csr_attrs(
				sm->cfg->eap_teapv2_csrattrs);
		if (!data->csr_attrs) {
			eap_teapv2_reset(sm, data);
			return NULL;
		}
	}
	data->cb_required = false;
	return data;
}


static void eap_teapv2_reset(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	if (!data)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->reset(sm, data->phase2_priv);
	eap_server_tls_ssl_deinit(sm, &data->ssl);
	wpabuf_free(data->pkcs7_cert);
	wpabuf_free(data->pkcs10_csr);
	os_free(data->srv_id);
	os_free(data->srv_id_info);
	wpabuf_free(data->pending_phase2_resp);
	wpabuf_free(data->server_outer_tlvs);
	wpabuf_free(data->peer_outer_tlvs);
	wpabuf_free(data->trusted_server_root);
	wpabuf_free(data->csr_attrs);
	os_free(data->identity);
	forced_memzero(data->simck_msk, EAP_TEAPV2_SIMCK_LEN);
	forced_memzero(data->simck_emsk, EAP_TEAPV2_SIMCK_LEN);
	forced_memzero(data->cmk_msk, EAP_TEAPV2_CMK_LEN);
	forced_memzero(data->cmk_emsk, EAP_TEAPV2_CMK_LEN);
	bin_clear_free(data, sizeof(*data));
}


static struct wpabuf * eap_teapv2_build_start(struct eap_sm *sm,
					    struct eap_teapv2_data *data, u8 id)
{
	struct wpabuf *req;
	size_t outer_tlv_len = sizeof(struct teapv2_tlv_hdr) + data->srv_id_len;
	const u8 *start, *end;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_TEAPV2,
			    1 + 4 + outer_tlv_len, EAP_CODE_REQUEST, id);
	if (!req) {
		wpa_printf(MSG_ERROR,
			   "EAP-TEAPV2: Failed to allocate memory for request");
		eap_teapv2_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, EAP_TLS_FLAGS_START | EAP_TEAPV2_FLAGS_OUTER_TLV_LEN |
		      data->teapv2_version);
	wpabuf_put_be32(req, outer_tlv_len);

	start = wpabuf_put(req, 0);

	/* RFC 7170, Section 4.2.2: Authority-ID TLV */
	eap_teapv2_put_tlv(req, TEAPV2_TLV_AUTHORITY_ID,
			 data->srv_id, data->srv_id_len);

	end = wpabuf_put(req, 0);
	wpabuf_free(data->server_outer_tlvs);
	data->server_outer_tlvs = wpabuf_alloc_copy(start, end - start);
	if (!data->server_outer_tlvs) {
		eap_teapv2_state(data, FAILURE);
		return NULL;
	}

	eap_teapv2_state(data, PHASE1);

	return req;
}


static int eap_teapv2_phase1_done(struct eap_sm *sm, struct eap_teapv2_data *data)
{
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Phase 1 done, starting Phase 2");

	if (!data->identity && sm->cfg->eap_teapv2_auth == 2) {
		const char *subject;

		subject = tls_connection_get_peer_subject(data->ssl.conn);
		if (subject) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Peer subject from Phase 1 client certificate: '%s'",
				   subject);
			data->identity = (u8 *) os_strdup(subject);
			data->identity_len = os_strlen(subject);
		}
	}

	data->tls_cs = tls_connection_get_cipher_suite(data->ssl.conn);
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: TLS cipher suite 0x%04x",
		   data->tls_cs);

	if (eap_teapv2_derive_key_auth(sm, data) < 0) {
		eap_teapv2_state(data, FAILURE);
		return -1;
	}

	data->request_pkcs10 = eap_teapv2_cert_near_expiry(sm, data) ||
		eap_teapv2_cert_not_signed_by_pkcs7(sm, data);
	if (data->request_pkcs10) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Peer certificate is past the 2/3 lifetime threshold - request PKCS#10 CSR");
	}

	eap_teapv2_state(data, PHASE2_START);

	return 0;
}


static struct wpabuf *
eap_teapv2_add_request_action(struct eap_teapv2_data *data,
			      struct wpabuf *msg)
{
	struct wpabuf *tlv, *csr_tlv = NULL;

	if (!msg || !data->request_pkcs10)
		return msg;
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Adding Request-Action TLV");
	tlv = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) + 4);
	if (!tlv) {
		wpabuf_free(msg);
		return NULL;
	}

	eap_teapv2_put_tlv_hdr(tlv, TEAPV2_TLV_REQUEST_ACTION, 4);
	wpabuf_put_u8(tlv, TEAPV2_STATUS_SUCCESS);
	wpabuf_put_u8(tlv, TEAPV2_REQUEST_ACTION_PROCESS_TLV);
	wpabuf_put_be16(tlv, TEAPV2_TLV_PKCS10);

	if (data->csr_attrs) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Add CSR-Attributes TLV (RFC 9908)");
		csr_tlv = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) +
				       wpabuf_len(data->csr_attrs));
		if (!csr_tlv) {
			wpabuf_free(msg);
			wpabuf_free(tlv);
			return NULL;
		}
		eap_teapv2_put_tlv_buf(csr_tlv, TEAPV2_TLV_CSR_ATTRS,
				       data->csr_attrs);
		tlv = wpabuf_concat(tlv, csr_tlv);
	}

	data->request_pkcs10 = false;
	data->pkcs10_expected = true;
	eap_teapv2_state(data, PHASE2_WAIT_PKCS10);
	return wpabuf_concat(msg, tlv);
}

static struct wpabuf *
eap_teapv2_add_trusted_server_root(struct eap_teapv2_data *data,
				   struct wpabuf *msg)
{
	struct wpabuf *tlv;

	if (!msg || !data->trusted_server_root)
		return msg;

	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Add Trusted-Server-Root TLV");
	tlv = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) + 2 +
			   wpabuf_len(data->trusted_server_root));
	if (!tlv) {
		wpabuf_free(msg);
		return NULL;
	}
	eap_teapv2_put_tlv_hdr(tlv, TEAPV2_TLV_TRUSTED_SERVER_ROOT,
			       2 + wpabuf_len(data->trusted_server_root));
	wpabuf_put_be16(tlv, 1);
	wpabuf_put_buf(tlv, data->trusted_server_root);

	return wpabuf_concat(msg, tlv);
}

static struct wpabuf *
eap_teapv2_add_pkcs7(struct eap_teapv2_data *data, struct wpabuf *msg)
{
	struct wpabuf *tlv;

	if (!data || !data->pkcs7_cert || data->pkcs10_expected)
		return msg;
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Generating PKCS7 TLV");
	tlv = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) +
			   wpabuf_len(data->pkcs7_cert));
	if (!tlv) {
		wpabuf_free(msg);
		return NULL;
	}

	eap_teapv2_put_tlv_hdr(tlv, TEAPV2_TLV_PKCS7,
			       wpabuf_len(data->pkcs7_cert));
	wpabuf_put_buf(tlv, data->pkcs7_cert);
	wpabuf_free(data->pkcs7_cert);
	data->pkcs7_cert = NULL;
	if (msg)
		return wpabuf_concat(msg, tlv);
	else
		return tlv;
}


static struct wpabuf * eap_teapv2_build_phase2_req(struct eap_sm *sm,
						 struct eap_teapv2_data *data,
						 u8 id)
{
	struct wpabuf *req, *id_tlv = NULL;

	if (sm->cfg->eap_teapv2_auth == 1 ||
	    (data->phase2_priv && data->phase2_method &&
	     data->phase2_method->vendor == EAP_VENDOR_IETF &&
	     data->phase2_method->method == EAP_TYPE_IDENTITY)) {
		switch (sm->cfg->eap_teapv2_id) {
		case EAP_TEAPV2_ID_ALLOW_ANY:
			break;
		case EAP_TEAPV2_ID_REQUIRE_USER:
		case EAP_TEAPV2_ID_REQUEST_USER_ACCEPT_MACHINE:
			data->cur_id_type = TEAPV2_IDENTITY_TYPE_USER;
			id_tlv = eap_teapv2_tlv_identity_type(data->cur_id_type);
			break;
		case EAP_TEAPV2_ID_REQUIRE_MACHINE:
		case EAP_TEAPV2_ID_REQUEST_MACHINE_ACCEPT_USER:
			data->cur_id_type = TEAPV2_IDENTITY_TYPE_MACHINE;
			id_tlv = eap_teapv2_tlv_identity_type(data->cur_id_type);
			break;
		case EAP_TEAPV2_ID_REQUIRE_USER_AND_MACHINE:
			if (data->cur_id_type == TEAPV2_IDENTITY_TYPE_USER)
				data->cur_id_type = TEAPV2_IDENTITY_TYPE_MACHINE;
			else
				data->cur_id_type = TEAPV2_IDENTITY_TYPE_USER;
			id_tlv = eap_teapv2_tlv_identity_type(data->cur_id_type);
			break;
		}
	}

	if (sm->cfg->eap_teapv2_auth == 1) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Initiate Basic-Password-Auth");
		data->basic_auth_not_done = 1;
		req = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr));
		if (!req) {
			wpabuf_free(id_tlv);
			return NULL;
		}
		eap_teapv2_put_tlv_hdr(req, TEAPV2_TLV_BASIC_PASSWORD_AUTH_REQ, 0);
		return eap_teapv2_add_request_action(data,
						     wpabuf_concat(req, id_tlv));
	}

	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Initiate inner EAP method");
	data->inner_eap_not_done = 1;
	if (!data->phase2_priv) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Phase 2 method not initialized");
		wpabuf_free(id_tlv);
		return NULL;
	}

	req = data->phase2_method->buildReq(sm, data->phase2_priv, id);
	if (!req) {
		wpabuf_free(id_tlv);
		return NULL;
	}

	wpa_hexdump_buf_key(MSG_MSGDUMP, "EAP-TEAPV2: Phase 2 EAP-Request", req);

	req = eap_teapv2_tlv_eap_payload(req);
	req = wpabuf_concat(req, id_tlv);
	req = eap_teapv2_add_request_action(data, req);
	return eap_teapv2_add_pkcs7(data, req);
}


static struct wpabuf * eap_teapv2_build_crypto_binding(
	struct wpabuf *buf, struct eap_teapv2_data *data) 
{
	struct teapv2_tlv_crypto_binding *cb;
	u8 subtype, flags;
	/* Crypto-Binding TLV */

	cb = wpabuf_put(buf, sizeof(*cb));
	cb->tlv_type = host_to_be16(TEAPV2_TLV_MANDATORY |
				    TEAPV2_TLV_CRYPTO_BINDING);
	cb->length = host_to_be16(sizeof(*cb) - sizeof(struct teapv2_tlv_hdr));
	cb->version = EAP_TEAPV2_VERSION;
	cb->received_version = data->peer_version;
	flags = data->cmk_emsk_available ?
		TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC :
		TEAPV2_CRYPTO_BINDING_MSK_CMAC;
	subtype = TEAPV2_CRYPTO_BINDING_SUBTYPE_REQUEST;
	cb->subtype = (flags << 4) | subtype;
	if (random_get_bytes(cb->nonce, sizeof(cb->nonce)) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	/*
	 * RFC 7170, Section 4.2.13:
	 * The nonce in a request MUST have its least significant bit set to 0.
	 */
	cb->nonce[sizeof(cb->nonce) - 1] &= ~0x01;

	os_memcpy(data->crypto_binding_nonce, cb->nonce, sizeof(cb->nonce));

	if (eap_teapv2_compound_mac(data->tls_cs, cb, data->server_outer_tlvs,
				  data->peer_outer_tlvs, data->cmk_msk,
				  cb->msk_compound_mac) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	if (data->cmk_emsk_available &&
	    eap_teapv2_compound_mac(data->tls_cs, cb, data->server_outer_tlvs,
				  data->peer_outer_tlvs, data->cmk_emsk,
				  cb->emsk_compound_mac) < 0) {
		wpabuf_free(buf);
		return NULL;
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Add Crypto-Binding TLV: Version %u Received Version %u Flags %u Sub-Type %u",
		   cb->version, cb->received_version, flags, subtype);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Nonce",
		    cb->nonce, sizeof(cb->nonce));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: EMSK Compound MAC",
		    cb->emsk_compound_mac, sizeof(cb->emsk_compound_mac));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: MSK Compound MAC",
		    cb->msk_compound_mac, sizeof(cb->msk_compound_mac));

	data->check_crypto_binding = true;
	return buf;
}


static struct wpabuf * eap_teapv2_result_maybe_crypto_binding(
	struct eap_sm *sm, struct eap_teapv2_data *data)
{
	struct wpabuf *buf;
	struct teapv2_tlv_result *result;

	buf = wpabuf_alloc(2 * sizeof(*result) + sizeof(struct teapv2_tlv_crypto_binding));
	if (!buf)
		return NULL;

	if (data->basic_auth_not_done || data->inner_eap_not_done || data->pkcs10_expected ||
	    data->request_pkcs10 || data->phase2_method || sm->cfg->eap_teapv2_separate_result)
		data->final_result = 0;
	else
		data->final_result = 1;

	if (!data->final_result || data->eap_seq > 0 ||
	    sm->cfg->eap_teapv2_auth == 1) {
		/* Intermediate-Result */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Add Intermediate-Result TLV (status=SUCCESS)");
		result = wpabuf_put(buf, sizeof(*result));
		result->tlv_type = host_to_be16(TEAPV2_TLV_MANDATORY |
						TEAPV2_TLV_INTERMEDIATE_RESULT);
		result->length = host_to_be16(2);
		result->status = host_to_be16(TEAPV2_STATUS_SUCCESS);
	}

	if (data->final_result) {
		/* Result TLV */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Add Result TLV (status=SUCCESS)");
		result = wpabuf_put(buf, sizeof(*result));
		result->tlv_type = host_to_be16(TEAPV2_TLV_MANDATORY |
						TEAPV2_TLV_RESULT);
		result->length = host_to_be16(2);
		result->status = host_to_be16(TEAPV2_STATUS_SUCCESS);
	}

	if (data->cb_required) {
		buf=eap_teapv2_build_crypto_binding(buf, data);
		data->cb_required = false;
		if (buf == NULL)
			return NULL;
	}
	buf = eap_teapv2_add_trusted_server_root(data, buf);
	buf = eap_teapv2_add_request_action(data, buf);
	return eap_teapv2_add_pkcs7(data, buf);
}


static int eap_teapv2_encrypt_phase2(struct eap_sm *sm,
				   struct eap_teapv2_data *data,
				   struct wpabuf *plain, int piggyback)
{
	struct wpabuf *encr;

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TEAPV2: Encrypting Phase 2 TLVs",
			    plain);
	encr = eap_server_tls_encrypt(sm, &data->ssl, plain);
	wpabuf_free(plain);

	if (!encr)
		return -1;

	if (data->ssl.tls_out && piggyback) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Piggyback Phase 2 data (len=%d) with last Phase 1 Message (len=%d used=%d)",
			   (int) wpabuf_len(encr),
			   (int) wpabuf_len(data->ssl.tls_out),
			   (int) data->ssl.tls_out_pos);
		if (wpabuf_resize(&data->ssl.tls_out, wpabuf_len(encr)) < 0) {
			wpa_printf(MSG_WARNING,
				   "EAP-TEAPV2: Failed to resize output buffer");
			wpabuf_free(encr);
			return -1;
		}
		wpabuf_put_buf(data->ssl.tls_out, encr);
		wpabuf_free(encr);
	} else {
		wpabuf_free(data->ssl.tls_out);
		data->ssl.tls_out_pos = 0;
		data->ssl.tls_out = encr;
	}

	return 0;
}


static struct wpabuf * eap_teapv2_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_teapv2_data *data = priv;
	struct wpabuf *req = NULL;
	int piggyback = 0;
	bool move_to_method = true;

	if (data->ssl.state == FRAG_ACK) {
		return eap_server_tls_build_ack(id, EAP_TYPE_TEAPV2,
						data->teapv2_version);
	}

	if (data->ssl.state == WAIT_FRAG_ACK) {
		return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_TEAPV2,
						data->teapv2_version, id);
	}

	switch (data->state) {
	case START:
		return eap_teapv2_build_start(sm, data, id);
	case PHASE1B:
		if (tls_connection_established(sm->cfg->ssl_ctx,
					       data->ssl.conn)) {
			if (eap_teapv2_phase1_done(sm, data) < 0)
				return NULL;
			if (data->state == PHASE2_START) {
				int res;

				/*
				 * Try to generate Phase 2 data to piggyback
				 * with the end of Phase 1 to avoid extra
				 * roundtrip.
				 */
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: Try to start Phase 2");
				res = eap_teapv2_process_phase2_start(sm, data);
				if (res == 1) {
					if (data->state == CRYPTO_BINDING) {
						wpa_printf(MSG_DEBUG,
							   "EAP-TEAPV2: Skip piggybacked Crypto-Binding after Phase 1 completion");
						eap_teapv2_state(data,
								 SUCCESS_SEND_RESULT);
					}
					req = eap_teapv2_tlv_result(
						TEAPV2_STATUS_SUCCESS, 0);
					req = eap_teapv2_add_request_action(
						data, req);
					req = eap_teapv2_add_pkcs7(data, req);
					data->final_result = 1;
					piggyback = 1;
					break;
				}

				if (res)
					break;
				req = eap_teapv2_build_phase2_req(sm, data, id);
				piggyback = 1;
			}
		}
		break;
	case PHASE2_ID:
	case PHASE2_BASIC_AUTH:
	case PHASE2_WAIT_PKCS10:
	case PHASE2_METHOD:
		req = eap_teapv2_build_phase2_req(sm, data, id);
		break;
	case CRYPTO_BINDING:
		req = eap_teapv2_result_maybe_crypto_binding(sm, data);
		if (req && sm->cfg->eap_teapv2_auth == 0 &&
		    data->inner_eap_not_done &&
		    !data->phase2_method &&
		    sm->cfg->eap_teapv2_method_sequence == 0) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Continue with inner EAP authentication for second credential (optimized)");
			eap_teapv2_state(data, PHASE2_ID);
			if (eap_teapv2_phase2_init(sm, data, EAP_VENDOR_IETF,
						 EAP_TYPE_IDENTITY) < 0) {
				eap_teapv2_state(data, FAILURE);
				wpabuf_free(req);
				return NULL;
			}
			move_to_method = false;
		}
		if (data->phase2_method) {
			/*
			 * Include the start of the next EAP method in the
			 * sequence in the same message with Crypto-Binding to
			 * save a round-trip.
			 */
			struct wpabuf *eap;

			eap = eap_teapv2_build_phase2_req(sm, data, id);
			req = wpabuf_concat(req, eap);
			if (move_to_method)
				eap_teapv2_state(data, PHASE2_METHOD);
		} else
			eap_teapv2_state(data,SUCCESS_SEND_RESULT);
		break;
	case FAILURE_SEND_RESULT:
		req = eap_teapv2_tlv_result(TEAPV2_STATUS_FAILURE, 0);
		if (data->error_code)
			req = wpabuf_concat(
				req, eap_teapv2_tlv_error(data->error_code));
		req = eap_teapv2_add_pkcs7(data, req);
		break;
	case PKCS7_READY:
		req = eap_teapv2_add_pkcs7(data, req);
		req = wpabuf_concat(req,
			eap_teapv2_tlv_result(TEAPV2_STATUS_SUCCESS, 0));
		data->final_result = 1;
		break;
	case SUCCESS_SEND_RESULT:
		req = eap_teapv2_tlv_result(TEAPV2_STATUS_SUCCESS, 0);
		data->final_result = 1;
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: %s - unexpected state %d",
			   __func__, data->state);
		return NULL;
	}

	if (req && eap_teapv2_encrypt_phase2(sm, data, req, piggyback) < 0)
		return NULL;

	return eap_server_tls_build_msg(&data->ssl, EAP_TYPE_TEAPV2,
					data->teapv2_version, id);
}


static bool eap_teapv2_check(struct eap_sm *sm, void *priv,
			   struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TEAPV2, respData, &len);
	if (!pos || len < 1) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: Invalid frame");
		return true;
	}

	return false;
}


static int eap_teapv2_phase2_init(struct eap_sm *sm, struct eap_teapv2_data *data,
				int vendor, enum eap_type eap_type)
{
	if (data->phase2_priv && data->phase2_method) {
		data->phase2_method->reset(sm, data->phase2_priv);
		data->phase2_method = NULL;
		data->phase2_priv = NULL;
	}
	data->phase2_method = eap_server_get_eap_method(vendor, eap_type);
	if (!data->phase2_method)
		return -1;

	/* While RFC 7170 does not describe this, EAP-TEAPV2 has been deployed
	 * with implementations that use the EAP-FAST-MSCHAPv2, instead of the
	 * EAP-MSCHAPv2, way of deriving the MSK for IMSK. Use that design here
	 * to interoperate.
	 */
	sm->eap_fast_mschapv2 = true;

	sm->init_phase2 = 1;
	data->phase2_priv = data->phase2_method->init(sm);
	sm->init_phase2 = 0;

	return data->phase2_priv ? 0 : -1;
}


static int eap_teapv2_valid_id_type(struct eap_sm *sm, struct eap_teapv2_data *data,
				  enum teapv2_identity_types id_type)
{
	if (sm->cfg->eap_teapv2_id == EAP_TEAPV2_ID_REQUIRE_USER &&
	    id_type != TEAPV2_IDENTITY_TYPE_USER)
		return 0;
	if (sm->cfg->eap_teapv2_id == EAP_TEAPV2_ID_REQUIRE_MACHINE &&
	    id_type != TEAPV2_IDENTITY_TYPE_MACHINE)
		return 0;
	if (sm->cfg->eap_teapv2_id == EAP_TEAPV2_ID_REQUIRE_USER_AND_MACHINE &&
	    id_type != data->cur_id_type)
		return 0;
	if (sm->cfg->eap_teapv2_id != EAP_TEAPV2_ID_ALLOW_ANY &&
	    id_type != TEAPV2_IDENTITY_TYPE_USER &&
	    id_type != TEAPV2_IDENTITY_TYPE_MACHINE)
		return 0;
	return 1;
}


static void eap_teapv2_process_phase2_response(struct eap_sm *sm,
					     struct eap_teapv2_data *data,
					     u8 *in_data, size_t in_len,
					     enum teapv2_identity_types id_type)
{
	int next_vendor = EAP_VENDOR_IETF;
	enum eap_type next_type = EAP_TYPE_NONE;
	struct eap_hdr *hdr;
	u8 *pos;
	size_t left;
	struct wpabuf buf;
	const struct eap_method *m = data->phase2_method;
	void *priv = data->phase2_priv;

	if (!priv) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: %s - Phase 2 not initialized?!",
			   __func__);
		return;
	}

	hdr = (struct eap_hdr *) in_data;
	pos = (u8 *) (hdr + 1);

	if (in_len > sizeof(*hdr) && *pos == EAP_TYPE_NAK) {
		left = in_len - sizeof(*hdr);
		wpa_hexdump(MSG_DEBUG,
			    "EAP-TEAPV2: Phase 2 type Nak'ed; allowed types",
			    pos + 1, left - 1);
#ifdef EAP_SERVER_TNC
		if (m && m->vendor == EAP_VENDOR_IETF &&
		    m->method == EAP_TYPE_TNC) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Peer Nak'ed required TNC negotiation");
			next_vendor = EAP_VENDOR_IETF;
			next_type = eap_teapv2_req_failure(data, 0);
			eap_teapv2_phase2_init(sm, data, next_vendor, next_type);
			return;
		}
#endif /* EAP_SERVER_TNC */
		eap_sm_process_nak(sm, pos + 1, left - 1);
		if (sm->user && sm->user_eap_method_index < EAP_MAX_METHODS &&
		    sm->user->methods[sm->user_eap_method_index].method !=
		    EAP_TYPE_NONE) {
			next_vendor = sm->user->methods[
				sm->user_eap_method_index].vendor;
			next_type = sm->user->methods[
				sm->user_eap_method_index++].method;
			wpa_printf(MSG_DEBUG, "EAP-TEAPV2: try EAP type %u:%u",
				   next_vendor, next_type);
		} else {
			next_vendor = EAP_VENDOR_IETF;
			next_type = eap_teapv2_req_failure(data, 0);
		}
		eap_teapv2_phase2_init(sm, data, next_vendor, next_type);
		return;
	}

	wpabuf_set(&buf, in_data, in_len);

	if (m->check(sm, priv, &buf)) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Phase 2 check() asked to ignore the packet");
		eap_teapv2_req_failure(data, TEAPV2_ERROR_INNER_METHOD);
		return;
	}

	m->process(sm, priv, &buf);

	if (!m->isDone(sm, priv))
		return;

	if (!m->isSuccess(sm, priv)) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Phase 2 method failed");
		next_vendor = EAP_VENDOR_IETF;
		next_type = eap_teapv2_req_failure(data, TEAPV2_ERROR_INNER_METHOD);
		data->inner_method_done = false;
		eap_teapv2_phase2_init(sm, data, next_vendor, next_type);
		return;
	}

	data->inner_method_done = true;
	data->cb_required = true;

	switch (data->state) {
	case PHASE2_ID:
		if (!eap_teapv2_valid_id_type(sm, data, id_type)) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Provided Identity-Type %u not allowed",
				   id_type);
			eap_teapv2_req_failure(data, TEAPV2_ERROR_INNER_METHOD);
			break;
		}
		if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
			wpa_hexdump_ascii(MSG_DEBUG,
					  "EAP-TEAPV2: Phase 2 Identity not found in the user database",
					  sm->identity, sm->identity_len);
			next_vendor = EAP_VENDOR_IETF;
			next_type = eap_teapv2_req_failure(
				data, TEAPV2_ERROR_INNER_METHOD);
			break;
		}

		eap_teapv2_state(data, PHASE2_METHOD);
		next_vendor = sm->user->methods[0].vendor;
		next_type = sm->user->methods[0].method;
		sm->user_eap_method_index = 1;
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Try EAP type %u:%u",
			   next_vendor, next_type);
		break;
	case PHASE2_METHOD:
	case CRYPTO_BINDING:
		eap_teapv2_update_icmk(sm, data);
		if (data->state == PHASE2_METHOD &&
		    (sm->cfg->eap_teapv2_id !=
		     EAP_TEAPV2_ID_REQUIRE_USER_AND_MACHINE ||
		     data->cur_id_type == TEAPV2_IDENTITY_TYPE_MACHINE))
			data->inner_eap_not_done = 0;
		eap_teapv2_state(data, CRYPTO_BINDING);
		data->eap_seq++;
		next_vendor = EAP_VENDOR_IETF;
		next_type = EAP_TYPE_NONE;
#ifdef EAP_SERVER_TNC
		if (sm->cfg->tnc && !data->tnc_started) {
			wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Initialize TNC");
			next_vendor = EAP_VENDOR_IETF;
			next_type = EAP_TYPE_TNC;
			data->tnc_started = 1;
		}
#endif /* EAP_SERVER_TNC */
		break;
	case FAILURE:
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: %s - unexpected state %d",
			   __func__, data->state);
		break;
	}

	eap_teapv2_phase2_init(sm, data, next_vendor, next_type);
}


static void eap_teapv2_process_phase2_eap(struct eap_sm *sm,
					struct eap_teapv2_data *data,
					u8 *in_data, size_t in_len,
					enum teapv2_identity_types id_type)
{
	struct eap_hdr *hdr;
	size_t len;

	hdr = (struct eap_hdr *) in_data;
	if (in_len < (int) sizeof(*hdr)) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Too short Phase 2 EAP frame (len=%lu)",
			   (unsigned long) in_len);
		eap_teapv2_req_failure(data, TEAPV2_ERROR_INNER_METHOD);
		return;
	}
	len = be_to_host16(hdr->length);
	if (len > in_len) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Length mismatch in Phase 2 EAP frame (len=%lu hdr->length=%lu)",
			   (unsigned long) in_len, (unsigned long) len);
		eap_teapv2_req_failure(data, TEAPV2_ERROR_INNER_METHOD);
		return;
	}
	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Received Phase 2: code=%d identifier=%d length=%lu",
		   hdr->code, hdr->identifier,
		   (unsigned long) len);
	switch (hdr->code) {
	case EAP_CODE_RESPONSE:
		eap_teapv2_process_phase2_response(sm, data, (u8 *) hdr, len,
						 id_type);
		break;
	default:
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Unexpected code=%d in Phase 2 EAP header",
			   hdr->code);
		break;
	}
}


static void eap_teapv2_process_basic_auth_resp(struct eap_sm *sm,
					     struct eap_teapv2_data *data,
					     u8 *in_data, size_t in_len,
					     enum teapv2_identity_types id_type)
{
	u8 *pos, *end, *username, *password, *new_id;
	u8 userlen, passlen;

	if (!eap_teapv2_valid_id_type(sm, data, id_type)) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Provided Identity-Type %u not allowed",
			   id_type);
		eap_teapv2_req_failure(data, 0);
		return;
	}

	pos = in_data;
	end = pos + in_len;

	if (end - pos < 1) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: No room for Basic-Password-Auth-Resp Userlen field");
		eap_teapv2_req_failure(data, 0);
		return;
	}
	userlen = *pos++;
	if (end - pos < userlen) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Truncated Basic-Password-Auth-Resp Username field");
		eap_teapv2_req_failure(data, 0);
		return;
	}
	username = pos;
	pos += userlen;
	wpa_hexdump_ascii(MSG_DEBUG,
			  "EAP-TEAPV2: Basic-Password-Auth-Resp Username",
			  username, userlen);

	if (end - pos < 1) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: No room for Basic-Password-Auth-Resp Passlen field");
		eap_teapv2_req_failure(data, 0);
		return;
	}
	passlen = *pos++;
	if (end - pos < passlen) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Truncated Basic-Password-Auth-Resp Password field");
		eap_teapv2_req_failure(data, 0);
		return;
	}
	password = pos;
	pos += passlen;
	wpa_hexdump_ascii_key(MSG_DEBUG,
			      "EAP-TEAPV2: Basic-Password-Auth-Resp Password",
			      password, passlen);

	if (end > pos) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Unexpected %d extra octet(s) at the end of Basic-Password-Auth-Resp TLV",
			   (int) (end - pos));
		eap_teapv2_req_failure(data, 0);
		return;
	}

	if (eap_user_get(sm, username, userlen, 1) != 0) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Username not found in the user database");
		eap_teapv2_req_failure(data, 0);
		return;
	}

	if (!sm->user || !sm->user->password || sm->user->password_hash) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: No plaintext user password configured");
		eap_teapv2_req_failure(data, 0);
		return;
	}

	if (sm->user->password_len != passlen ||
	    os_memcmp_const(sm->user->password, password, passlen) != 0) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Invalid password");
		eap_teapv2_req_failure(data, 0);
		return;
	}

	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Correct password");
	new_id = os_memdup(username, userlen);
	if (new_id) {
		os_free(sm->identity);
		sm->identity = new_id;
		sm->identity_len = userlen;
	}
	if (sm->cfg->eap_teapv2_id != EAP_TEAPV2_ID_REQUIRE_USER_AND_MACHINE ||
	    data->cur_id_type == TEAPV2_IDENTITY_TYPE_MACHINE)
		data->basic_auth_not_done = 0;
	if (data->basic_auth_not_done)
		eap_teapv2_state(data, PHASE2_BASIC_AUTH);
	else
		eap_teapv2_state(data, SUCCESS_SEND_RESULT);
	eap_teapv2_update_icmk(sm, data);
}


static int eap_teapv2_parse_tlvs(struct wpabuf *data,
			       struct eap_teapv2_tlv_parse *tlv)
{
	u16 tlv_type;
	int mandatory, res;
	size_t len;
	u8 *pos, *end;

	os_memset(tlv, 0, sizeof(*tlv));

	pos = wpabuf_mhead(data);
	end = pos + wpabuf_len(data);
	while (end - pos > 4) {
		mandatory = pos[0] & 0x80;
		tlv_type = WPA_GET_BE16(pos) & 0x3fff;
		pos += 2;
		len = WPA_GET_BE16(pos);
		pos += 2;
		if (len > (size_t) (end - pos)) {
			wpa_printf(MSG_INFO, "EAP-TEAPV2: TLV overflow");
			return -1;
		}
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Received Phase 2: TLV type %u (%s) length %u%s",
			   tlv_type, eap_teapv2_tlv_type_str(tlv_type),
			   (unsigned int) len,
			   mandatory ? " (mandatory)" : "");

		res = eap_teapv2_parse_tlv(tlv, tlv_type, pos, len);
		if (res == -2)
			break;
		if (res < 0) {
			if (mandatory) {
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: NAK unknown mandatory TLV type %u",
					   tlv_type);
				/* TODO: generate NAK TLV */
				break;
			}

			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Ignore unknown optional TLV type %u",
				   tlv_type);
		}

		pos += len;
	}

	return 0;
}


static int eap_teapv2_validate_crypto_binding(
	struct eap_teapv2_data *data, const struct teapv2_tlv_crypto_binding *cb,
	size_t bind_len)
{
	u8 flags, subtype;

	subtype = cb->subtype & 0x0f;
	flags = cb->subtype >> 4;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Reply Crypto-Binding TLV: Version %u Received Version %u Flags %u Sub-Type %u",
		   cb->version, cb->received_version, flags, subtype);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Nonce",
		    cb->nonce, sizeof(cb->nonce));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: EMSK Compound MAC",
		    cb->emsk_compound_mac, sizeof(cb->emsk_compound_mac));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: MSK Compound MAC",
		    cb->msk_compound_mac, sizeof(cb->msk_compound_mac));

	if (cb->version != EAP_TEAPV2_VERSION ||
	    cb->received_version != data->peer_version) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Unexpected version in Crypto-Binding: Version %u Received Version %u",
			   cb->version, cb->received_version);
		return -1;
	}

	if (flags < 1 || flags > 3) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Unexpected Flags in Crypto-Binding: %u",
			   flags);
		return -1;
	}

	if (subtype != TEAPV2_CRYPTO_BINDING_SUBTYPE_RESPONSE) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Unexpected Sub-Type in Crypto-Binding: %u",
			   subtype);
		return -1;
	}

	if (os_memcmp_const(data->crypto_binding_nonce, cb->nonce,
			    EAP_TEAPV2_NONCE_LEN - 1) != 0 ||
	    (data->crypto_binding_nonce[EAP_TEAPV2_NONCE_LEN - 1] | 1) !=
	    cb->nonce[EAP_TEAPV2_NONCE_LEN - 1]) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Invalid Nonce in Crypto-Binding");
		return -1;
	}

	if (flags == TEAPV2_CRYPTO_BINDING_MSK_CMAC ||
	    flags == TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC) {
		u8 msk_compound_mac[EAP_TEAPV2_COMPOUND_MAC_LEN];

		if (eap_teapv2_compound_mac(data->tls_cs, cb,
					  data->server_outer_tlvs,
					  data->peer_outer_tlvs, data->cmk_msk,
					  msk_compound_mac) < 0)
			return -1;
		if (os_memcmp_const(msk_compound_mac, cb->msk_compound_mac,
				    EAP_TEAPV2_COMPOUND_MAC_LEN) != 0) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TEAPV2: Calculated MSK Compound MAC",
				    msk_compound_mac,
				    EAP_TEAPV2_COMPOUND_MAC_LEN);
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: MSK Compound MAC did not match");
			return -1;
		}
	}

	if ((flags == TEAPV2_CRYPTO_BINDING_EMSK_CMAC ||
	     flags == TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC) &&
	    data->cmk_emsk_available) {
		u8 emsk_compound_mac[EAP_TEAPV2_COMPOUND_MAC_LEN];

		if (eap_teapv2_compound_mac(data->tls_cs, cb,
					  data->server_outer_tlvs,
					  data->peer_outer_tlvs, data->cmk_emsk,
					  emsk_compound_mac) < 0)
			return -1;
		if (os_memcmp_const(emsk_compound_mac, cb->emsk_compound_mac,
				    EAP_TEAPV2_COMPOUND_MAC_LEN) != 0) {
			wpa_hexdump(MSG_DEBUG,
				    "EAP-TEAPV2: Calculated EMSK Compound MAC",
				    emsk_compound_mac,
				    EAP_TEAPV2_COMPOUND_MAC_LEN);
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: EMSK Compound MAC did not match");
			return -1;
		}
	}

	if (flags == TEAPV2_CRYPTO_BINDING_EMSK_CMAC &&
	    !data->cmk_emsk_available) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Peer included only EMSK Compound MAC, but no locally generated inner EAP EMSK to validate this");
		return -1;
	}

	if (data->cmk_emsk_available &&
	    (flags == TEAPV2_CRYPTO_BINDING_EMSK_CMAC ||
	     flags == TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC)) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Selected S-IMCK_EMSK");
		os_memcpy(data->simck, data->simck_emsk, EAP_TEAPV2_SIMCK_LEN);
	} else if (flags == TEAPV2_CRYPTO_BINDING_MSK_CMAC ||
		   flags == TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Selected S-IMCK_EMSK");
		os_memcpy(data->simck, data->simck_msk, EAP_TEAPV2_SIMCK_LEN);
	}
	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: Selected S-IMCK[j]",
			data->simck, EAP_TEAPV2_SIMCK_LEN);

	return 0;
}


static void eap_teapv2_process_phase2_tlvs(struct eap_sm *sm,
					 struct eap_teapv2_data *data,
					 struct wpabuf *in_data)
{
	struct eap_teapv2_tlv_parse tlv;
	bool check_crypto_binding = data->check_crypto_binding;

	if (eap_teapv2_parse_tlvs(in_data, &tlv) < 0) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Failed to parse received Phase 2 TLVs");
		return;
	}

	if (tlv.result == TEAPV2_STATUS_FAILURE) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Result TLV indicated failure");
		eap_teapv2_state(data, FAILURE);
		return;
	}

	if (tlv.nak) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Peer NAK'ed Vendor-Id %u NAK-Type %u",
			   WPA_GET_BE32(tlv.nak), WPA_GET_BE16(tlv.nak + 4));
		eap_teapv2_state(data, FAILURE_SEND_RESULT);
		return;
	}

		if (tlv.pkcs10) {
			size_t b64_len;
			char *b64 = base64_encode(tlv.pkcs10, tlv.pkcs10_len,
							&b64_len);

		if (b64) {
			size_t pem_len = b64_len + b64_len / 64 + 96;
			char *pem = os_malloc(pem_len);

			if (pem) {
				char *pos = pem;
				size_t left = pem_len;
				size_t i;

				pos += os_strlcpy(pos,
							"-----BEGIN CERTIFICATE REQUEST-----\n",
							left);
				left = pem_len - (pos - pem);

				for (i = 0; i < b64_len && left > 1;
						i += 64) {
					size_t line = b64_len - i;

					if (line > 64)
						line = 64;
					pos += os_snprintf(pos, left,
								"%.*s",
								(int) line,
								b64 + i);
					left = pem_len - (pos - pem);
				}

				if (left > 0) {
					os_strlcpy(pos,
							"-----END CERTIFICATE REQUEST-----",
							left);
					wpa_printf(MSG_DEBUG,
							"EAP-TEAPV2: Received PKCS#10 CSR (PEM)\n%s",
							pem);
				}
				os_free(pem);
			}
			os_free(b64);
		}
		wpabuf_free(data->pkcs7_cert);
		data->pkcs7_cert = tls_connection_sign_pkcs7(
			sm->cfg->ssl_ctx, tlv.pkcs10, tlv.pkcs10_len,
			sm->cfg->teapv2_pkcs7_cert ?
			sm->cfg->teapv2_pkcs7_cert : sm->cfg->server_cert,
			sm->cfg->teapv2_pkcs7_key ?
			sm->cfg->teapv2_pkcs7_key : sm->cfg->private_key);
		wpabuf_free(data->pkcs10_csr);
		data->pkcs10_csr = wpabuf_alloc_copy(tlv.pkcs10,
								tlv.pkcs10_len);
		data->pkcs10_expected = false;
		if (data->pkcs7_cert) {
			eap_teapv2_state(data, PKCS7_READY);
			wpa_printf(MSG_DEBUG,
					"EAP-TEAPV2: Prepared PKCS#7 response (%u bytes)",
					(unsigned int) wpabuf_len(data->pkcs7_cert));
		} else {
			wpa_printf(MSG_INFO,
					"EAP-TEAPV2: Failed to prepare PKCS#7 response");
			}
		}

		if (check_crypto_binding) {
			if (!tlv.crypto_binding) {
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: No Crypto-Binding TLV received");
				eap_teapv2_state(data, FAILURE);
			return;
		}

		if (!data->inner_method_done) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Unexpected Crypto-Binding TLV before successful inner EAP method completion");
			eap_teapv2_state(data, FAILURE);
			return;
		}

		if (data->final_result &&
		    tlv.result != TEAPV2_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Crypto-Binding TLV without Success Result");
			eap_teapv2_state(data, FAILURE);
			return;
		}

		if (sm->cfg->eap_teapv2_auth != 1 &&
		    !data->skipped_inner_auth &&
		    tlv.iresult != TEAPV2_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Crypto-Binding TLV without intermediate Success Result");
			eap_teapv2_state(data, FAILURE);
			return;
		}

		if (eap_teapv2_validate_crypto_binding(data, tlv.crypto_binding,
						     tlv.crypto_binding_len)) {
			eap_teapv2_state(data, FAILURE);
			return;
		}

		if (data->pkcs10_expected && !tlv.pkcs10 &&
		    tlv.result == TEAPV2_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: PKCS#10 CSR not received when requested; allowing authentication to complete");
			data->pkcs10_expected = false;
		}

		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Valid Crypto-Binding TLV received");
		data->check_crypto_binding = false;
		data->inner_method_done = false;
	}

	if (data->final_result) {
		wpa_printf(MSG_DEBUG,
				"EAP-TEAPV2: Authentication completed successfully");
		if (data->final_result)
		  eap_teapv2_state(data, SUCCESS);
		else if (sm->cfg->eap_teapv2_separate_result)
		  eap_teapv2_state(data, SUCCESS_SEND_RESULT);

	}
	if (data->inner_method_done && !tlv.crypto_binding)
		data->inner_method_done = false;

	if (tlv.basic_auth_resp) {
		if (sm->cfg->eap_teapv2_auth != 1) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Unexpected Basic-Password-Auth-Resp when trying to use inner EAP");
			eap_teapv2_state(data, FAILURE);
			return;
		}
		eap_teapv2_process_basic_auth_resp(sm, data, tlv.basic_auth_resp,
						 tlv.basic_auth_resp_len,
						 tlv.identity_type);
	}

	if (tlv.eap_payload_tlv) {
		if (sm->cfg->eap_teapv2_auth == 1) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Unexpected EAP Payload TLV when trying to use Basic-Password-Auth");
			eap_teapv2_state(data, FAILURE);
			return;
		}
		eap_teapv2_process_phase2_eap(sm, data, tlv.eap_payload_tlv,
					    tlv.eap_payload_tlv_len,
					    tlv.identity_type);
	}

	if ((data->state == SUCCESS_SEND_RESULT ||
	     data->state == PKCS7_READY) &&
	    tlv.result == TEAPV2_STATUS_SUCCESS) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Peer agreed with final success - authentication completed");
		eap_teapv2_state(data, SUCCESS);
	} else if (check_crypto_binding && data->state == CRYPTO_BINDING &&
		   sm->cfg->eap_teapv2_auth == 1 && data->basic_auth_not_done) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Continue with basic password authentication for second credential");
		eap_teapv2_state(data, PHASE2_BASIC_AUTH);
	} else if (check_crypto_binding && data->state == CRYPTO_BINDING &&
		   sm->cfg->eap_teapv2_auth == 0 && data->inner_eap_not_done &&
		   sm->cfg->eap_teapv2_method_sequence == 1) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Continue with inner EAP authentication for second credential");
		eap_teapv2_state(data, PHASE2_ID);
		if (eap_teapv2_phase2_init(sm, data, EAP_VENDOR_IETF,
					 EAP_TYPE_IDENTITY) < 0)
			eap_teapv2_state(data, FAILURE);
	}
}


static void eap_teapv2_process_phase2(struct eap_sm *sm,
				    struct eap_teapv2_data *data,
				    struct wpabuf *in_buf)
{
	struct wpabuf *in_decrypted;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Received %lu bytes encrypted data for Phase 2",
		   (unsigned long) wpabuf_len(in_buf));

	if (data->pending_phase2_resp) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Pending Phase 2 response - skip decryption and use old data");
		eap_teapv2_process_phase2_tlvs(sm, data,
					     data->pending_phase2_resp);
		wpabuf_free(data->pending_phase2_resp);
		data->pending_phase2_resp = NULL;
		return;
	}

	in_decrypted = tls_connection_decrypt(sm->cfg->ssl_ctx, data->ssl.conn,
					      in_buf);
	if (!in_decrypted) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to decrypt Phase 2 data");
		eap_teapv2_state(data, FAILURE);
		return;
	}

	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TEAPV2: Decrypted Phase 2 TLVs",
			    in_decrypted);

	eap_teapv2_process_phase2_tlvs(sm, data, in_decrypted);

	if (sm->method_pending == METHOD_PENDING_WAIT) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Phase 2 method is in pending wait state - save decrypted response");
		wpabuf_free(data->pending_phase2_resp);
		data->pending_phase2_resp = in_decrypted;
		return;
	}

	wpabuf_free(in_decrypted);
}


static int eap_teapv2_process_version(struct eap_sm *sm, void *priv,
				    int peer_version)
{
	struct eap_teapv2_data *data = priv;

	if (peer_version < 1) {
		/* Version 1 was the first defined version, so reject 0 */
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Peer used unknown TEAPV2 version %u",
			   peer_version);
		return -1;
	}

	if (peer_version < data->teapv2_version) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: peer ver=%u, own ver=%u; "
			   "use version %u",
			   peer_version, data->teapv2_version, peer_version);
		data->teapv2_version = peer_version;
	}

	data->peer_version = peer_version;

	return 0;
}


static int eap_teapv2_process_phase1(struct eap_sm *sm,
				   struct eap_teapv2_data *data)
{
	if (eap_server_tls_phase1(sm, &data->ssl) < 0) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: TLS processing failed");
		eap_teapv2_state(data, FAILURE);
		return -1;
	}

	if (!tls_connection_established(sm->cfg->ssl_ctx, data->ssl.conn) ||
	    wpabuf_len(data->ssl.tls_out) > 0)
		return 1;

	/*
	 * Phase 1 was completed with the received message (e.g., when using
	 * abbreviated handshake), so Phase 2 can be started immediately
	 * without having to send through an empty message to the peer.
	 */

	return eap_teapv2_phase1_done(sm, data);
}


static int eap_teapv2_process_phase2_start(struct eap_sm *sm,
					 struct eap_teapv2_data *data)
{
	int next_vendor;
	enum eap_type next_type;

	if (data->identity) {
		/* Identity is from client certificate */
		os_free(sm->identity);
		sm->identity = data->identity;
		data->identity = NULL;
		sm->identity_len = data->identity_len;
		data->identity_len = 0;
		if (eap_user_get(sm, sm->identity, sm->identity_len, 1) != 0) {
			wpa_hexdump_ascii(MSG_DEBUG,
					  "EAP-TEAPV2: Phase 2 Identity not found in the user database",
					  sm->identity, sm->identity_len);
			next_vendor = EAP_VENDOR_IETF;
			next_type = EAP_TYPE_NONE;
			eap_teapv2_state(data, PHASE2_METHOD);
		} else if (sm->cfg->eap_teapv2_auth == 2) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Used client certificate and identity already known - skip inner auth");
			data->skipped_inner_auth = 1;
			if (eap_teapv2_derive_imck(data->tls_cs, data->simck,
						 NULL, 0, NULL, 0,
						 data->simck_msk, data->cmk_msk,
						 data->simck_emsk,
						 data->cmk_emsk))
				return -1; /* XXX This code is wrong, because the return state is either 0 or 1: there is no way
							* to produce an error at this point.
							*/
			eap_teapv2_state(data, CRYPTO_BINDING);
			return 1;
		} else if (sm->cfg->eap_teapv2_auth == 1) {
			eap_teapv2_state(data, PHASE2_BASIC_AUTH);
			return 0;
		} else {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Identity already known - skip Phase 2 Identity Request");
			next_vendor = sm->user->methods[0].vendor;
			next_type = sm->user->methods[0].method;
			sm->user_eap_method_index = 1;
			eap_teapv2_state(data, PHASE2_METHOD);
		}

	} else if (sm->cfg->eap_teapv2_auth == 1) {
		eap_teapv2_state(data, PHASE2_BASIC_AUTH);
		return 0;
	} else {
		eap_teapv2_state(data, PHASE2_ID);
		next_vendor = EAP_VENDOR_IETF;
		next_type = EAP_TYPE_IDENTITY;
	}

	return eap_teapv2_phase2_init(sm, data, next_vendor, next_type);
}


static void eap_teapv2_process_msg(struct eap_sm *sm, void *priv,
				 const struct wpabuf *respData)
{
	struct eap_teapv2_data *data = priv;

	switch (data->state) {
	case PHASE1:
	case PHASE1B:
		if (eap_teapv2_process_phase1(sm, data))
			break;

		/* fall through */
	case PHASE2_START:
		eap_teapv2_process_phase2_start(sm, data);
		break;
	case PHASE2_ID:
	case PHASE2_BASIC_AUTH:
	case PHASE2_WAIT_PKCS10:
	case PHASE2_METHOD:
	case CRYPTO_BINDING:
	case PKCS7_READY:
	case SUCCESS_SEND_RESULT:
		eap_teapv2_process_phase2(sm, data, data->ssl.tls_in);
		break;
	case FAILURE_SEND_RESULT:
		/* Protected failure result indication completed. Ignore the
		 * received message (which is supposed to include Result TLV
		 * indicating failure) and terminate exchange with cleartext
		 * EAP-Failure. */
		eap_teapv2_state(data, FAILURE);
		break;
	default:
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Unexpected state %d in %s",
			   data->state, __func__);
		break;
	}
}


static void eap_teapv2_process(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	struct eap_teapv2_data *data = priv;
	const u8 *pos;
	size_t len;
	struct wpabuf *resp = respData;
	u8 flags;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TEAPV2, respData, &len);
	if (!pos || len < 1)
		return;

	flags = *pos++;
	len--;

	if (flags & EAP_TEAPV2_FLAGS_OUTER_TLV_LEN) {
		/* Extract Outer TLVs from the message before common TLS
		 * processing */
		u32 message_len = 0, outer_tlv_len;
		const u8 *hdr;

		if (data->state != PHASE1) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Unexpected Outer TLVs in a message that is not the first message from the peer");
			return;
		}

		if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED) {
			if (len < 4) {
				wpa_printf(MSG_INFO,
					   "EAP-TEAPV2: Too short message to include Message Length field");
				return;
			}

			message_len = WPA_GET_BE32(pos);
			pos += 4;
			len -= 4;
			if (message_len < 4) {
				wpa_printf(MSG_INFO,
					   "EAP-TEAPV2: Message Length field has too msall value to include Outer TLV Length field");
				return;
			}
		}

		if (len < 4) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short message to include Outer TLVs Length field");
			return;
		}

		outer_tlv_len = WPA_GET_BE32(pos);
		pos += 4;
		len -= 4;

		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Message Length %u Outer TLV Length %u",
			  message_len, outer_tlv_len);
		if (len < outer_tlv_len) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short message to include Outer TLVs field");
			return;
		}

		if (message_len &&
		    (message_len < outer_tlv_len ||
		     message_len < 4 + outer_tlv_len)) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Message Length field has too small value to include Outer TLVs");
			return;
		}

		if (wpabuf_len(respData) < 4 + outer_tlv_len ||
		    len < outer_tlv_len)
			return;
		resp = wpabuf_alloc(wpabuf_len(respData) - 4 - outer_tlv_len);
		if (!resp)
			return;
		hdr = wpabuf_head(respData);
		wpabuf_put_u8(resp, *hdr++); /* Code */
		wpabuf_put_u8(resp, *hdr++); /* Identifier */
		wpabuf_put_be16(resp, WPA_GET_BE16(hdr) - 4 - outer_tlv_len);
		hdr += 2;
		wpabuf_put_u8(resp, *hdr++); /* Type */
		/* Flags | Ver */
		wpabuf_put_u8(resp, flags & ~EAP_TEAPV2_FLAGS_OUTER_TLV_LEN);

		if (flags & EAP_TLS_FLAGS_LENGTH_INCLUDED)
			wpabuf_put_be32(resp, message_len - 4 - outer_tlv_len);

		wpabuf_put_data(resp, pos, len - outer_tlv_len);
		pos += len - outer_tlv_len;
		wpabuf_free(data->peer_outer_tlvs);
		data->peer_outer_tlvs = wpabuf_alloc_copy(pos, outer_tlv_len);
		if (!data->peer_outer_tlvs)
			return;
		wpa_hexdump_buf(MSG_DEBUG, "EAP-TEAPV2: Outer TLVs",
				data->peer_outer_tlvs);

		wpa_hexdump_buf(MSG_DEBUG,
				"EAP-TEAPV2: TLS Data message after Outer TLV removal",
				resp);
		pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_TEAPV2, resp,
				       &len);
		if (!pos || len < 1) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Invalid frame after Outer TLV removal");
			return;
		}
	}

	if (data->state == PHASE1)
		eap_teapv2_state(data, PHASE1B);

	if (eap_server_tls_process(sm, &data->ssl, resp, data,
				   EAP_TYPE_TEAPV2, eap_teapv2_process_version,
				   eap_teapv2_process_msg) < 0)
		eap_teapv2_state(data, FAILURE);

	if (resp != respData)
		wpabuf_free(resp);
}


static bool eap_teapv2_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_teapv2_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_teapv2_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	eapKeyData = os_malloc(EAP_TEAPV2_KEY_LEN);
	if (!eapKeyData)
		return NULL;

	if (eap_teapv2_derive_eap_msk(data->tls_cs, data->simck,
				    eapKeyData) < 0) {
		os_free(eapKeyData);
		wpa_printf(MSG_ERROR,"TEAPv2: could not derive MSK");
		return NULL;
	}
	*len = EAP_TEAPV2_KEY_LEN;

	return eapKeyData;
}


static u8 * eap_teapv2_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_teapv2_data *data = priv;
	u8 *eapKeyData;

	if (data->state != SUCCESS)
		return NULL;

	eapKeyData = os_malloc(EAP_EMSK_LEN);
	if (!eapKeyData)
		return NULL;

	if (eap_teapv2_derive_eap_emsk(data->tls_cs, data->simck,
				     eapKeyData) < 0) {
		os_free(eapKeyData);
		return NULL;
	}
	*len = EAP_EMSK_LEN;

	return eapKeyData;
}


static bool eap_teapv2_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	return data->state == SUCCESS;
}


static u8 * eap_teapv2_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_teapv2_data *data = priv;
	const size_t max_id_len = 100;
	int res;
	u8 *id;

	if (data->state != SUCCESS)
		return NULL;

	id = os_malloc(max_id_len);
	if (!id)
		return NULL;

	id[0] = EAP_TYPE_TEAPV2;
	res = tls_get_tls_unique(data->ssl.conn, id + 1, max_id_len - 1);
	if (res < 0) {
		os_free(id);
		wpa_printf(MSG_ERROR, "EAP-TEAPV2: Failed to derive Session-Id");
		return NULL;
	}

	*len = 1 + res;
	wpa_hexdump(MSG_DEBUG, "EAP-TEAPV2: Derived Session-Id", id, *len);
	return id;
}


int eap_server_teapv2_register(void)
{
	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_TEAPV2, "TEAPV2");
	if (!eap)
		return -1;

	eap->init = eap_teapv2_init;
	eap->reset = eap_teapv2_reset;
	eap->buildReq = eap_teapv2_buildReq;
	eap->check = eap_teapv2_check;
	eap->process = eap_teapv2_process;
	eap->isDone = eap_teapv2_isDone;
	eap->getKey = eap_teapv2_getKey;
	eap->get_emsk = eap_teapv2_get_emsk;
	eap->isSuccess = eap_teapv2_isSuccess;
	eap->getSessionId = eap_teapv2_get_session_id;

	return eap_server_method_register(eap);
}
