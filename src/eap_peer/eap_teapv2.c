/*
 * EAP peer method: EAP-TEAPV2 (RFC 7170)
 * Copyright (c) 2004-2024, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/crypto.h"
#include "crypto/tls.h"
#include "eap_common/eap_teapv2_common.h"
#include "eap_i.h"
#include "eap_tls_common.h"
#include "base64.h"
#include "tls/asn1.h"
#include "eap_config.h"
#ifdef CONFIG_TLS_INTERNAL
#include "tls/x509v3.h"
#endif


static void eap_teapv2_deinit(struct eap_sm *sm, void *priv);


struct eap_teapv2_data {
	struct eap_ssl_data ssl;

	u8 teapv2_version; /* Negotiated version */
	u8 received_version; /* Version number received during negotiation */
	u16 tls_cs;

	const struct eap_method *phase2_method;
	void *phase2_priv;
	int phase2_success;
	int inner_method_done;
	int iresult_verified;
	int result_success_done;
	int on_tx_completion;

	struct eap_method_type phase2_type;
	struct eap_method_type *phase2_types;
	size_t num_phase2_types;
	int resuming; /* starting a resumed session */
	int test_outer_tlvs;

	u8 key_data[EAP_TEAPV2_KEY_LEN];
	u8 *session_id;
	size_t id_len;
	u8 emsk[EAP_EMSK_LEN];
	int success;

	u8 simck[EAP_TEAPV2_SIMCK_LEN];
	u8 simck_msk[EAP_TEAPV2_SIMCK_LEN];
	u8 simck_emsk[EAP_TEAPV2_SIMCK_LEN];
	int simck_idx;
	bool cmk_emsk_available;
	bool pkcs10_requested;
	bool pkcs7_success;
	bool cb_required;
	bool client_authenticated;
	struct wpabuf *csr_attrs;

	struct wpabuf *pending_phase2_req;
	struct wpabuf *pending_resp;
	struct wpabuf *server_outer_tlvs;
	struct wpabuf *peer_outer_tlvs;

	enum teapv2_compat { // XXX needs to go.
		TEAPV2_DEFAULT,
		TEAPV2_FREERADIUS,
	} teapv2_compat;
};

static struct eap_peer_cert_config *
eap_teapv2_current_cert_config(struct eap_sm *sm)
{
	struct eap_peer_config *config = eap_get_config(sm);

	if (!config)
		return NULL;

	if (sm->use_machine_cred)
		return &config->machine_cert;

	return &config->cert;
}


static int eap_teapv2_store_blob(struct eap_sm *sm,
				 struct eap_peer_cert_config *cert,
				 const char *purpose, const u8 *data,
				 size_t len, char **dst)
{
	struct wpa_config_blob *blob;
	char name[64];
	char *ref = NULL;

	if (!sm || !cert || !purpose || !data || !dst)
		return -1;

	blob = os_zalloc(sizeof(*blob));
	if (!blob)
		return -1;

	os_snprintf(name, sizeof(name), "teapv2-%s-%p", purpose, cert);
	blob->name = os_strdup(name);
	blob->data = os_memdup(data, len);
	if (!blob->name || !blob->data) {
		os_free(blob->name);
		os_free(blob->data);
		os_free(blob);
		return -1;
	}
	blob->len = len;

	ref = os_malloc(7 + os_strlen(name) + 1);
	if (!ref) {
		os_free(blob->name);
		os_free(blob->data);
		os_free(blob);
		return -1;
	}
	os_snprintf(ref, 7 + os_strlen(name) + 1, "blob://%s", name);

	eap_set_config_blob(sm, blob);

	os_free(*dst);
	*dst = ref;
	return 0;
}

static void
eap_teapv2_process_trusted_server_root(struct eap_sm *sm, const u8 *buf,
				       size_t len)
{
	struct eap_peer_cert_config *cert_cfg;
	u16 format;
	const u8 *cred;
	size_t cred_len;
	char *ref = NULL;

	if (!buf || len < 2)
		return;

	format = WPA_GET_BE16(buf);
	cred = buf + 2;
	cred_len = len - 2;
	if (cred_len == 0)
		return;

	cert_cfg = eap_teapv2_current_cert_config(sm);
	if (!cert_cfg) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: No certificate configuration for Trusted-Server-Root TLV");
		return;
	}

	if (format == 1) {
		if (eap_teapv2_store_blob(sm, cert_cfg, "trusted-root",
					  cred, cred_len,
					  &cert_cfg->ca_cert) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to store Trusted-Server-Root");
			return;
		}
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Installed Trusted-Server-Root as trust anchor");
	} else {
		if (eap_teapv2_store_blob(sm, cert_cfg, "trusted-root",
					  cred, cred_len, &ref) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to store Trusted-Server-Root");
			return;
		}
		os_free(ref);
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Stored Trusted-Server-Root (format=%u, len=%u)",
		   format, (unsigned int) cred_len);
}


static int eap_teapv2_set_csr_subject_from_identity(struct eap_sm *sm,
						    struct crypto_csr *csr)
{
	const u8 *identity = NULL;
	size_t identity_len = 0;
	struct eap_peer_config *config = eap_get_config(sm);
	char *tmp;
	int ret;

	if (sm->identity) {
		identity = sm->identity;
		identity_len = sm->identity_len;
	} else if (config && config->identity && config->identity_len) {
		identity = config->identity;
		identity_len = config->identity_len;
	}

	if (!identity || !identity_len)
		return -1;

	tmp = os_malloc(identity_len + 1);
	if (!tmp)
		return -1;
	os_memcpy(tmp, identity, identity_len);
	tmp[identity_len] = '\0';

	ret = crypto_csr_set_name(csr, CSR_NAME_CN, tmp);
	os_free(tmp);
	return ret;
}


#ifdef CONFIG_TLS_INTERNAL
static int eap_teapv2_set_csr_subject_from_cert(struct crypto_csr *csr,
						struct x509_certificate *cert)
{
	size_t i;
	bool added = false;

	if (!csr || !cert)
		return -1;

	for (i = 0; i < cert->subject.num_attr; i++) {
		enum crypto_csr_name name;
		const struct x509_name_attr *attr = &cert->subject.attr[i];

		if (!attr->value)
			continue;

		switch (attr->type) {
		case X509_NAME_ATTR_CN:
			name = CSR_NAME_CN;
			break;
		case X509_NAME_ATTR_C:
			name = CSR_NAME_C;
			break;
		case X509_NAME_ATTR_O:
			name = CSR_NAME_O;
			break;
		case X509_NAME_ATTR_OU:
			name = CSR_NAME_OU;
			break;
		case X509_NAME_ATTR_ST:
			name = CSR_NAME_SN;
			break;
		default:
			continue;
		}

		if (crypto_csr_set_name(csr, name, attr->value) < 0)
			return -1;
		added = true;
	}

	return added ? 0 : -1;
}
#endif /* CONFIG_TLS_INTERNAL */


static int eap_teapv2_populate_csr_subject(struct eap_sm *sm,
					   struct crypto_csr *csr,
					   const struct wpabuf *own_cert)
{
#ifdef CONFIG_TLS_INTERNAL
	struct x509_certificate *cert = NULL;

	if (own_cert) {
		cert = x509_certificate_parse(wpabuf_head(own_cert),
					      wpabuf_len(own_cert));
		if (cert && eap_teapv2_set_csr_subject_from_cert(csr, cert) == 0) {
			x509_certificate_free(cert);
			return 0;
		}
		x509_certificate_free(cert);
	}
#else /* CONFIG_TLS_INTERNAL */
	(void) own_cert;
#endif /* CONFIG_TLS_INTERNAL */

	if (eap_teapv2_set_csr_subject_from_identity(sm, csr) == 0)
		return 0;

	return -1;
}

static int eap_teapv2_apply_csr_attrs(struct crypto_csr *csr,
				      const struct wpabuf *csr_attrs,
				      bool *name_set)
{
	const u8 *pos, *end, *seq_end;
	struct asn1_hdr hdr, set_hdr, val_hdr;
	struct asn1_oid oid;
	int ret = 0;

	if (name_set)
		*name_set = false;
	if (!csr || !csr_attrs)
		return 0;

	pos = wpabuf_head(csr_attrs);
	end = pos + wpabuf_len(csr_attrs);

	if (asn1_get_sequence(pos, end - pos, &hdr, &seq_end) < 0 ||
	    seq_end != end) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Invalid CSR Attributes DER");
		return -1;
	}

	pos = hdr.payload;
	while (pos < seq_end) {
		const u8 *attr_pos, *attr_end;

		if (asn1_get_next(pos, seq_end - pos, &hdr) < 0)
			return -1;

		if (hdr.class == ASN1_CLASS_UNIVERSAL &&
		    hdr.tag == ASN1_TAG_OID) {
			/* AttrOrOID with just OID - ignore */
			pos = hdr.payload + hdr.length;
			continue;
		}

		if (hdr.class != ASN1_CLASS_UNIVERSAL ||
		    hdr.tag != ASN1_TAG_SEQUENCE) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Ignore unexpected CSR Attributes element (class=%u tag=%u)",
				   hdr.class, hdr.tag);
			pos = hdr.payload + hdr.length;
			continue;
		}

		/* Attribute ::= SEQUENCE { type OID, values SET OF AttributeValue } */
		attr_pos = hdr.payload;
		attr_end = hdr.payload + hdr.length;
		if (asn1_get_oid(attr_pos, attr_end - attr_pos, &oid,
				 &attr_pos) < 0)
			return -1;

		if (asn1_get_next(attr_pos, attr_end - attr_pos, &set_hdr) < 0 ||
		    !asn1_is_set(&set_hdr)) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: CSR Attributes missing SET OF values");
			return -1;
		}

		attr_pos = set_hdr.payload;
		if (attr_pos >= set_hdr.payload + set_hdr.length) {
			/* Empty SET */
			pos = attr_end;
			continue;
		}

		if (asn1_get_next(attr_pos,
				  set_hdr.payload + set_hdr.length - attr_pos,
				  &val_hdr) < 0)
			return -1;

		if (!asn1_is_string_type(&val_hdr)) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Ignore non-string CSR Attribute value (tag 0x%x)",
				   val_hdr.tag);
			pos = attr_end;
			continue;
		}

		/* id-at ::= 2.5.4 */
		if (oid.len == 4 &&
		    oid.oid[0] == 2 && oid.oid[1] == 5 && oid.oid[2] == 4) {
			enum crypto_csr_name name = CSR_NAME_CN;
			bool supported = true;
			char *tmp;

			switch (oid.oid[3]) {
			case 3:
				name = CSR_NAME_CN;
				break;
			case 4:
				name = CSR_NAME_SN;
				break;
			case 6:
				name = CSR_NAME_C;
				break;
			case 10:
				name = CSR_NAME_O;
				break;
			case 11:
				name = CSR_NAME_OU;
				break;
			default:
				supported = false;
				break;
			}

			if (supported) {
				tmp = os_malloc(val_hdr.length + 1);
				if (!tmp)
					return -1;
				os_memcpy(tmp, val_hdr.payload, val_hdr.length);
				tmp[val_hdr.length] = '\0';
				if (crypto_csr_set_name(csr, name, tmp) < 0) {
					wpa_printf(MSG_INFO,
						   "EAP-TEAPV2: Failed to set CSR subject name");
					ret = -1;
				} else if (name_set) {
					*name_set = true;
				}
				os_free(tmp);
			}
		} else if (oid.len == 7 &&
			   oid.oid[0] == 1 && oid.oid[1] == 2 &&
			   oid.oid[2] == 840 && oid.oid[3] == 113549 &&
			   oid.oid[4] == 1 && oid.oid[5] == 9 &&
			   oid.oid[6] == 7) {
			/* pkcs-9-at-challengePassword */
			if (crypto_csr_set_attribute(
				    csr, CSR_ATTR_CHALLENGE_PASSWORD,
				    val_hdr.tag, val_hdr.payload,
				    val_hdr.length) < 0) {
				wpa_printf(MSG_INFO,
					   "EAP-TEAPV2: Failed to set CSR challengePassword");
				ret = -1;
			}
		}

		pos = attr_end;
	}

	return ret;
}


static struct wpabuf *
eap_teapv2_build_pkcs10_tlv(struct eap_sm *sm, struct eap_teapv2_data *data)
{
	struct crypto_ec_key *key = NULL;
	struct wpabuf *priv = NULL, *csr_der = NULL, *tlv = NULL;
	struct crypto_csr *csr = NULL;
	struct wpabuf *own_cert = NULL;
	struct eap_peer_cert_config *cert_cfg;
	const char *purpose;
	bool name_set = false;

	cert_cfg = eap_teapv2_current_cert_config(sm);
	if (!cert_cfg) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: No certificate configuration available for PKCS#10");
		return NULL;
	}

	key = crypto_ec_key_gen(19);
	if (!key)
		goto fail;

	priv = crypto_ec_key_get_ecprivate_key(key, true);
	if (!priv)
		goto fail;

	csr = crypto_csr_init();
	if (!csr || crypto_csr_set_ec_public_key(csr, key))
		goto fail;

	own_cert = tls_connection_get_own_cert(data->ssl.conn);
	if (data->csr_attrs) {
		wpa_hexdump_buf(MSG_MSGDUMP,
				"EAP-TEAPV2: CSR Attributes (RFC 9908)",
				data->csr_attrs);
		if (eap_teapv2_apply_csr_attrs(csr, data->csr_attrs,
					       &name_set) < 0)
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to apply CSR Attributes");
	}
	if (!name_set) {
		if (eap_teapv2_populate_csr_subject(sm, csr, own_cert) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to set CSR subject from existing credentials");
			goto fail;
		}
	}
	wpabuf_free(own_cert);
	own_cert = NULL;

	csr_der = crypto_csr_sign(csr, key, CRYPTO_HASH_ALG_SHA256);
	if (!csr_der)
		goto fail;
	wpa_hexdump_buf(MSG_MSGDUMP, "EAP-TEAPV2: PKCS#10 CSR (DER)",
			csr_der);
	{
		size_t b64_len;
		char *b64 = base64_encode(wpabuf_head(csr_der),
					  wpabuf_len(csr_der), &b64_len);

		if (b64) {
			/* Room for PEM headers/footers and newlines every 64 chars */
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

				for (i = 0; i < b64_len && left > 1; i += 64) {
					size_t line = b64_len - i;
					if (line > 64)
						line = 64;
					pos += os_snprintf(pos, left, "%.*s",
							   (int) line, b64 + i);
					left = pem_len - (pos - pem);
				}

				if (left > 0) {
					os_strlcpy(pos,
						   "-----END CERTIFICATE REQUEST-----",
						   left);
					wpa_printf(MSG_DEBUG,
						   "EAP-TEAPV2: PKCS#10 CSR (PEM)\n%s",
						   pem);
				}
				os_free(pem);
			}
			os_free(b64);
		}
	}

	purpose = sm->use_machine_cred ? "machine-key" : "user-key";
	if (eap_teapv2_store_blob(sm, cert_cfg, purpose,
				  wpabuf_head(priv), wpabuf_len(priv),
				  &cert_cfg->private_key) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to store generated private key");
		goto fail;
	}

	tlv = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) +
			   wpabuf_len(csr_der));
	if (!tlv)
		goto fail;
	eap_teapv2_put_tlv_buf(tlv, TEAPV2_TLV_PKCS10, csr_der);
	data->pkcs10_requested = true;
	wpabuf_free(data->csr_attrs);
	data->csr_attrs = NULL;

fail:
	wpabuf_free(data->csr_attrs);
	data->csr_attrs = NULL;
	wpabuf_clear_free(priv);
	wpabuf_free(csr_der);
	crypto_csr_deinit(csr);
	crypto_ec_key_deinit(key);
	wpabuf_free(own_cert);
	return tlv;
}


static int eap_teapv2_process_pkcs7(struct eap_sm *sm,
				    struct eap_teapv2_data *data,
				    const u8 *pkcs7, size_t len)
{
	struct wpabuf *src = NULL, *pem = NULL;
	struct eap_peer_cert_config *cert_cfg;
	const char *purpose;
	int ret = -1;

	cert_cfg = eap_teapv2_current_cert_config(sm);
	if (!cert_cfg)
		return -1;

	src = wpabuf_alloc_copy(pkcs7, len);
	if (!src)
		return -1;

	pem = crypto_pkcs7_get_certificates(src);
	if (!pem) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Could not parse PKCS#7 certificate bundle");
		goto done;
	}

	if (!data->pkcs10_requested) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Ignoring unsolicited PKCS#7 certificate");
		goto done;
	}

	purpose = sm->use_machine_cred ? "machine-cert" : "user-cert";
	if (eap_teapv2_store_blob(sm, cert_cfg, purpose,
				  wpabuf_head(pem), wpabuf_len(pem),
				  &cert_cfg->client_cert) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to store received PKCS#7 certificate");
		goto done;
	}

	wpa_printf(MSG_INFO,
		   "EAP-TEAPV2: Installed %s certificate from PKCS#7",
		   sm->use_machine_cred ? "machine" : "user");
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Installed certificate (PEM)\n%.*s",
		   (int) wpabuf_len(pem), (const char *) wpabuf_head(pem));
	data->pkcs10_requested = false;
	ret = 0;

done:
	wpabuf_free(src);
	wpabuf_free(pem);
	return ret;
}

static void eap_teapv2_parse_phase1(struct eap_teapv2_data *data,
				  const char *phase1)
{
#ifdef CONFIG_TESTING_OPTIONS
	if (os_strstr(phase1, "teapv2_test_outer_tlvs=1"))
		data->test_outer_tlvs = 1;
#endif /* CONFIG_TESTING_OPTIONS */

	if (os_strstr(phase1, "teapv2_compat=freeradius")) // XXX Needs to go.
		data->teapv2_compat = TEAPV2_FREERADIUS;
}


static void * eap_teapv2_init(struct eap_sm *sm)
{
	struct eap_teapv2_data *data;
	struct eap_peer_config *config = eap_get_config(sm);

	if (!config)
		return NULL;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;
	data->teapv2_version = EAP_TEAPV2_VERSION;

	if (config->phase1)
		eap_teapv2_parse_phase1(data, config->phase1);

	if (eap_peer_select_phase2_methods(config, "auth=",
					   &data->phase2_types,
					   &data->num_phase2_types, 0) < 0) {
		eap_teapv2_deinit(sm, data);
		return NULL;
	}

	data->phase2_type.vendor = EAP_VENDOR_IETF;
	data->phase2_type.method = EAP_TYPE_NONE;

	if (eap_peer_tls_ssl_init(sm, &data->ssl, config, EAP_TYPE_TEAPV2)) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: Failed to initialize SSL");
		eap_teapv2_deinit(sm, data);
		return NULL;
	}

	return data;
}


static void eap_teapv2_clear(struct eap_teapv2_data *data)
{
	forced_memzero(data->key_data, EAP_TEAPV2_KEY_LEN);
	forced_memzero(data->emsk, EAP_EMSK_LEN);
	os_free(data->session_id);
	data->session_id = NULL;
	wpabuf_free(data->pending_phase2_req);
	data->pending_phase2_req = NULL;
	wpabuf_free(data->pending_resp);
	data->pending_resp = NULL;
	wpabuf_free(data->server_outer_tlvs);
	data->server_outer_tlvs = NULL;
	wpabuf_free(data->peer_outer_tlvs);
	data->peer_outer_tlvs = NULL;
	wpabuf_free(data->csr_attrs);
	data->csr_attrs = NULL;
	forced_memzero(data->simck, EAP_TEAPV2_SIMCK_LEN);
	forced_memzero(data->simck_msk, EAP_TEAPV2_SIMCK_LEN);
	forced_memzero(data->simck_emsk, EAP_TEAPV2_SIMCK_LEN);
	data->pkcs7_success = false;
	data->client_authenticated = false;
	data->cb_required = true;
}


static void eap_teapv2_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	if (!data)
		return;
	if (data->phase2_priv && data->phase2_method)
		data->phase2_method->deinit(sm, data->phase2_priv);
	eap_teapv2_clear(data);
	os_free(data->phase2_types);
	eap_peer_tls_ssl_deinit(sm, &data->ssl);

	os_free(data);
}


static int eap_teapv2_derive_msk(struct eap_teapv2_data *data)
{
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Derive MSK/EMSK (n=%d)",
		   data->simck_idx);
	wpa_hexdump(MSG_DEBUG, "EAP-TEAPV2: S-IMCK[n]", data->simck,
		    EAP_TEAPV2_SIMCK_LEN);

	if (eap_teapv2_derive_eap_msk(data->tls_cs, data->simck,
				    data->key_data) < 0 ||
	    eap_teapv2_derive_eap_emsk(data->tls_cs, data->simck,
				     data->emsk) < 0)
		return -1;
	data->success = 1;
	return 0;
}


static int eap_teapv2_derive_key_auth(struct eap_sm *sm,
				    struct eap_teapv2_data *data)
{
	int res;

	/* RFC 7170, Section 5.1 */
	res = tls_connection_export_key(sm->ssl_ctx, data->ssl.conn,
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


static int eap_teapv2_init_phase2_method(struct eap_sm *sm,
				       struct eap_teapv2_data *data)
{
	data->inner_method_done = 0;
	data->iresult_verified = 0;
	data->pkcs7_success = false;
	data->phase2_method =
		eap_peer_get_eap_method(data->phase2_type.vendor,
					data->phase2_type.method);
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

	return data->phase2_priv == NULL ? -1 : 0;
}


static int eap_teapv2_select_phase2_method(struct eap_teapv2_data *data,
					 int vendor, enum eap_type type)
{
	size_t i;

#ifdef EAP_TNC
	if (vendor == EAP_VENDOR_IETF && type == EAP_TYPE_TNC) {
		data->phase2_type.vendor = EAP_VENDOR_IETF;
		data->phase2_type.method = EAP_TYPE_TNC;
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Selected Phase 2 EAP vendor %d method %d for TNC",
			   data->phase2_type.vendor,
			   data->phase2_type.method);
		return 0;
	}
#endif /* EAP_TNC */

	for (i = 0; i < data->num_phase2_types; i++) {
		if (data->phase2_types[i].vendor != vendor ||
		    data->phase2_types[i].method != type)
			continue;

		data->phase2_type.vendor = data->phase2_types[i].vendor;
		data->phase2_type.method = data->phase2_types[i].method;
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Selected Phase 2 EAP vendor %d method %d",
			   data->phase2_type.vendor,
			   data->phase2_type.method);
		break;
	}

	if (vendor != data->phase2_type.vendor ||
	    type != data->phase2_type.method ||
	    (vendor == EAP_VENDOR_IETF && type == EAP_TYPE_NONE))
		return -1;

	return 0;
}


static void eap_teapv2_deinit_inner_eap(struct eap_sm *sm,
				      struct eap_teapv2_data *data)
{
	if (!data->phase2_priv || !data->phase2_method)
		return;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Phase 2 EAP sequence - deinitialize previous method");
	data->phase2_method->deinit(sm, data->phase2_priv);
	data->phase2_method = NULL;
	data->phase2_priv = NULL;
	data->phase2_type.vendor = EAP_VENDOR_IETF;
	data->phase2_type.method = EAP_TYPE_NONE;
}


static int eap_teapv2_phase2_request(struct eap_sm *sm,
				   struct eap_teapv2_data *data,
				   struct eap_method_ret *ret,
				   struct eap_hdr *hdr,
				   struct wpabuf **resp)
{
	size_t len = be_to_host16(hdr->length);
	u8 *pos;
	struct eap_method_ret iret;
	struct eap_peer_config *config = eap_get_config(sm);
	struct wpabuf msg;
	int vendor = EAP_VENDOR_IETF;
	enum eap_type method;

	if (len <= sizeof(struct eap_hdr)) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: too short Phase 2 request (len=%lu)",
			   (unsigned long) len);
		return -1;
	}
	pos = (u8 *) (hdr + 1);
	method = *pos;
	if (method == EAP_TYPE_EXPANDED) {
		if (len < sizeof(struct eap_hdr) + 8) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Too short Phase 2 request (expanded header) (len=%lu)",
				   (unsigned long) len);
			return -1;
		}
		vendor = WPA_GET_BE24(pos + 1);
		method = WPA_GET_BE32(pos + 4);
	}
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Phase 2 Request: type=%u:%u",
		   vendor, method);
	if (vendor == EAP_VENDOR_IETF && method == EAP_TYPE_IDENTITY) {
		eap_teapv2_deinit_inner_eap(sm, data);
		*resp = eap_sm_buildIdentity(sm, hdr->identifier, 1);
		return 0;
	}

	if (data->phase2_priv && data->phase2_method &&
	    (vendor != data->phase2_type.vendor ||
	     method != data->phase2_type.method))
		eap_teapv2_deinit_inner_eap(sm, data);

	if (data->phase2_type.vendor == EAP_VENDOR_IETF &&
	    data->phase2_type.method == EAP_TYPE_NONE &&
	    eap_teapv2_select_phase2_method(data, vendor, method) < 0) {
		if (eap_peer_tls_phase2_nak(data->phase2_types,
					    data->num_phase2_types,
					    hdr, resp))
			return -1;
		return 0;
	}

	if ((!data->phase2_priv && eap_teapv2_init_phase2_method(sm, data) < 0) ||
	    !data->phase2_method) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to initialize Phase 2 EAP method %u:%u",
			   vendor, method);
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return -1;
	}

	os_memset(&iret, 0, sizeof(iret));
	wpabuf_set(&msg, hdr, len);
	*resp = data->phase2_method->process(sm, data->phase2_priv, &iret,
					     &msg);
	if (iret.methodState == METHOD_DONE)
		data->inner_method_done = 1;

	if (!(*resp) ||
	    (iret.methodState == METHOD_DONE &&
	     iret.decision == DECISION_FAIL)) {
		/* Wait for protected indication of failure */
		ret->methodState = METHOD_MAY_CONT;
		ret->decision = DECISION_FAIL;
	} else if ((iret.methodState == METHOD_DONE ||
		    iret.methodState == METHOD_MAY_CONT) &&
		   (iret.decision == DECISION_UNCOND_SUCC ||
		    iret.decision == DECISION_COND_SUCC)) {
		data->phase2_success = 1;
	}

	if (!(*resp) && config &&
	    (config->pending_req_identity || config->pending_req_password ||
	     config->pending_req_otp || config->pending_req_new_password ||
	     config->pending_req_sim)) {
		wpabuf_free(data->pending_phase2_req);
		data->pending_phase2_req = wpabuf_alloc_copy(hdr, len);
	} else if (!(*resp))
		return -1;

	return 0;
}


static struct wpabuf * eap_teapv2_tlv_nak(int vendor_id, int tlv_type)
{
	struct wpabuf *buf;
	struct teapv2_tlv_nak *nak;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Add NAK TLV (Vendor-Id %u NAK-Type %u)",
		   vendor_id, tlv_type);
	buf = wpabuf_alloc(sizeof(*nak));
	if (!buf)
		return NULL;
	nak = wpabuf_put(buf, sizeof(*nak));
	nak->tlv_type = host_to_be16(TEAPV2_TLV_MANDATORY | TEAPV2_TLV_NAK);
	nak->length = host_to_be16(6);
	nak->vendor_id = host_to_be32(vendor_id);
	nak->nak_type = host_to_be16(tlv_type);
	return buf;
}


static struct wpabuf * eap_teapv2_add_identity_type(struct eap_sm *sm,
						  struct wpabuf *msg)
{
	struct wpabuf *tlv;

	tlv = eap_teapv2_tlv_identity_type(sm->use_machine_cred ?
					 TEAPV2_IDENTITY_TYPE_MACHINE :
					 TEAPV2_IDENTITY_TYPE_USER);
	return wpabuf_concat(msg, tlv);
}


static struct wpabuf * eap_teapv2_process_eap_payload_tlv(
	struct eap_sm *sm, struct eap_teapv2_data *data,
	struct eap_method_ret *ret,
	u8 *eap_payload_tlv, size_t eap_payload_tlv_len,
	enum teapv2_identity_types req_id_type)
{
	struct eap_hdr *hdr;
	struct wpabuf *resp = NULL;

	if (eap_payload_tlv_len < sizeof(*hdr)) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: too short EAP Payload TLV (len=%lu)",
			   (unsigned long) eap_payload_tlv_len);
		return NULL;
	}

	hdr = (struct eap_hdr *) eap_payload_tlv;
	if (be_to_host16(hdr->length) > eap_payload_tlv_len) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: EAP packet overflow in EAP Payload TLV");
		return NULL;
	}

	if (hdr->code != EAP_CODE_REQUEST) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Unexpected code=%d in Phase 2 EAP header",
			   hdr->code);
		return NULL;
	}

	if (eap_teapv2_phase2_request(sm, data, ret, hdr, &resp)) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Phase 2 Request processing failed");
		return NULL;
	}

	resp = eap_teapv2_tlv_eap_payload(resp);
	if (req_id_type)
		resp = eap_teapv2_add_identity_type(sm, resp);

	return resp;
}


static struct wpabuf * eap_teapv2_process_basic_auth_req(
	struct eap_sm *sm, struct eap_teapv2_data *data,
	u8 *basic_auth_req, size_t basic_auth_req_len,
	enum teapv2_identity_types req_id_type)
{
	const u8 *identity, *password;
	size_t identity_len, password_len, plen;
	struct wpabuf *resp;

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-TEAPV2: Basic-Password-Auth-Req prompt",
			  basic_auth_req, basic_auth_req_len);
	/* TODO: send over control interface */

	identity = eap_get_config_identity(sm, &identity_len);
	password = eap_get_config_password(sm, &password_len);
	if (!identity || !password ||
	    identity_len > 255 || password_len > 255) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: No username/password suitable for Basic-Password-Auth");
		return eap_teapv2_tlv_nak(0, TEAPV2_TLV_BASIC_PASSWORD_AUTH_REQ);
	}

	plen = 1 + identity_len + 1 + password_len;
	resp = wpabuf_alloc(sizeof(struct teapv2_tlv_hdr) + plen);
	if (!resp)
		return NULL;
	eap_teapv2_put_tlv_hdr(resp, TEAPV2_TLV_BASIC_PASSWORD_AUTH_RESP, plen);
	wpabuf_put_u8(resp, identity_len);
	wpabuf_put_data(resp, identity, identity_len);
	wpabuf_put_u8(resp, password_len);
	wpabuf_put_data(resp, password, password_len);
	wpa_hexdump_buf_key(MSG_DEBUG, "EAP-TEAPV2: Basic-Password-Auth-Resp",
			    resp);
	if (req_id_type)
		resp = eap_teapv2_add_identity_type(sm, resp);

	/* Assume this succeeds so that Result TLV(Success) from the server can
	 * be used to terminate TEAPV2. */
	data->phase2_success = 1;
	data->cb_required = false;

	return resp;
}


static int
eap_teapv2_validate_crypto_binding(struct eap_teapv2_data *data,
				 const struct teapv2_tlv_crypto_binding *cb)
{
	u8 flags, subtype;

	subtype = cb->subtype & 0x0f;
	flags = cb->subtype >> 4;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Crypto-Binding TLV: Version %u Received Version %u Flags %u Sub-Type %u",
		   cb->version, cb->received_version, flags, subtype);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Nonce",
		    cb->nonce, sizeof(cb->nonce));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: EMSK Compound MAC",
		    cb->emsk_compound_mac, sizeof(cb->emsk_compound_mac));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: MSK Compound MAC",
		    cb->msk_compound_mac, sizeof(cb->msk_compound_mac));

	if (cb->version != EAP_TEAPV2_VERSION ||
	    cb->received_version != data->received_version ||
	    subtype != TEAPV2_CRYPTO_BINDING_SUBTYPE_REQUEST ||
	    flags < 1 || flags > 3) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Invalid Version/Flags/Sub-Type in Crypto-Binding TLV: Version %u Received Version %u Flags %u Sub-Type %u",
			   cb->version, cb->received_version, flags, subtype);
		return -1;
	}

	if (cb->nonce[EAP_TEAPV2_NONCE_LEN - 1] & 0x01) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Invalid Crypto-Binding TLV Nonce in request");
		return -1;
	}

	return 0;
}


static int eap_teapv2_write_crypto_binding(
	struct eap_teapv2_data *data,
	struct teapv2_tlv_crypto_binding *rbind,
	const struct teapv2_tlv_crypto_binding *cb,
	const u8 *cmk_msk, const u8 *cmk_emsk)
{
	u8 subtype, flags;

	rbind->tlv_type = host_to_be16(TEAPV2_TLV_MANDATORY |
				       TEAPV2_TLV_CRYPTO_BINDING);
	rbind->length = host_to_be16(sizeof(*rbind) -
				     sizeof(struct teapv2_tlv_hdr));
	rbind->version = EAP_TEAPV2_VERSION;
	rbind->received_version = data->received_version;
	subtype = TEAPV2_CRYPTO_BINDING_SUBTYPE_RESPONSE;
	if (cmk_emsk)
		flags = TEAPV2_CRYPTO_BINDING_EMSK_CMAC;
	else if (cmk_msk)
		flags = TEAPV2_CRYPTO_BINDING_MSK_CMAC;
	else
		return -1;
	rbind->subtype = (flags << 4) | subtype;
	os_memcpy(rbind->nonce, cb->nonce, sizeof(cb->nonce));
	inc_byte_array(rbind->nonce, sizeof(rbind->nonce));
	os_memset(rbind->emsk_compound_mac, 0, EAP_TEAPV2_COMPOUND_MAC_LEN);
	os_memset(rbind->msk_compound_mac, 0, EAP_TEAPV2_COMPOUND_MAC_LEN);

	if (cmk_msk &&
	    eap_teapv2_compound_mac(data->tls_cs, rbind, data->server_outer_tlvs,
				  data->peer_outer_tlvs, cmk_msk,
				  rbind->msk_compound_mac) < 0)
		return -1;
	if (cmk_emsk &&
	    eap_teapv2_compound_mac(data->tls_cs, rbind, data->server_outer_tlvs,
				  data->peer_outer_tlvs, cmk_emsk,
				  rbind->emsk_compound_mac) < 0)
		return -1;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Reply Crypto-Binding TLV: Version %u Received Version %u Flags %u SubType %u",
		   rbind->version, rbind->received_version, flags, subtype);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Nonce",
		    rbind->nonce, sizeof(rbind->nonce));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: EMSK Compound MAC",
		    rbind->emsk_compound_mac, sizeof(rbind->emsk_compound_mac));
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: MSK Compound MAC",
		    rbind->msk_compound_mac, sizeof(rbind->msk_compound_mac));

	return 0;
}


static int eap_teapv2_get_cmk(struct eap_sm *sm, struct eap_teapv2_data *data,
			    u8 *cmk_msk, u8 *cmk_emsk)
{
	u8 *msk = NULL, *emsk = NULL;
	size_t msk_len = 0, emsk_len = 0;
	int res;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Determining CMK[%d] for Compound MAC calculation",
		   data->simck_idx + 1);

	if (!data->phase2_method)
		goto out; /* no MSK derived in Basic-Password-Auth */

	if (!data->phase2_method || !data->phase2_priv) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: Phase 2 method not available");
		return -1;
	}

	if (data->phase2_method->isKeyAvailable &&
	    !data->phase2_method->isKeyAvailable(sm, data->phase2_priv)) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Phase 2 key material not available");
		return -1;
	}

	if (data->phase2_method->isKeyAvailable &&
	    data->phase2_method->getKey) {
		msk = data->phase2_method->getKey(sm, data->phase2_priv,
						  &msk_len);
		if (!msk) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Could not fetch Phase 2 MSK");
			return -1;
		}
	}

	if (data->phase2_method->isKeyAvailable &&
	    data->phase2_method->get_emsk) {
		emsk = data->phase2_method->get_emsk(sm, data->phase2_priv,
						     &emsk_len);
	}

out:
	if (data->teapv2_compat == TEAPV2_FREERADIUS) { // XXX should not be in TEAPv2.  One behavior.
		u8 tmp_simck[EAP_TEAPV2_SIMCK_LEN];
		u8 tmp_cmk[EAP_TEAPV2_CMK_LEN];

		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: FreeRADIUS compatibility: use S-IMCK_MSK[j-1] and S-IMCK_EMSK[j-1] based on MSK/EMSK derivations instead of a single selected S-IMCK[j-1]");
		res = eap_teapv2_derive_imck(data->tls_cs, data->simck_msk,
					   msk, msk_len, emsk, emsk_len,
					   data->simck_msk, cmk_msk,
					   tmp_simck, tmp_cmk);
		if (emsk)
			res = eap_teapv2_derive_imck(data->tls_cs,
						   data->simck_emsk,
						   msk, msk_len, emsk, emsk_len,
						   tmp_simck, tmp_cmk,
						   data->simck_emsk, cmk_emsk);
	} else {
		res = eap_teapv2_derive_imck(data->tls_cs, data->simck,
					   msk, msk_len, emsk, emsk_len,
					   data->simck_msk, cmk_msk,
					   data->simck_emsk, cmk_emsk);
	}
	bin_clear_free(msk, msk_len);
	bin_clear_free(emsk, emsk_len);
	if (res == 0) {
		data->simck_idx++;
		data->cmk_emsk_available = emsk != NULL;
	}
	return res;
}


static int eap_teapv2_session_id(struct eap_teapv2_data *data)
{
	const size_t max_id_len = 100;
	int res;

	os_free(data->session_id);
	data->session_id = os_malloc(max_id_len);
	if (!data->session_id)
		return -1;

	data->session_id[0] = EAP_TYPE_TEAPV2;
	res = tls_get_tls_unique(data->ssl.conn, data->session_id + 1,
				 max_id_len - 1);
	if (res < 0 || (size_t) res >= max_id_len) {
		os_free(data->session_id);
		data->session_id = NULL;
		wpa_printf(MSG_ERROR, "EAP-TEAPV2: Failed to derive Session-Id");
		return -1;
	}

	data->id_len = 1 + res;
	wpa_hexdump(MSG_DEBUG, "EAP-TEAPV2: Derived Session-Id",
		    data->session_id, data->id_len);
	return 0;
}


static struct wpabuf * eap_teapv2_process_crypto_binding(
	struct eap_sm *sm, struct eap_teapv2_data *data,
	struct eap_method_ret *ret,
	const struct teapv2_tlv_crypto_binding *cb, size_t bind_len)
{
	struct wpabuf *resp;
	u8 *pos;
	u8 cmk_msk[EAP_TEAPV2_CMK_LEN];
	u8 cmk_emsk[EAP_TEAPV2_CMK_LEN];
	const u8 *cmk_msk_ptr = NULL;
	const u8 *cmk_emsk_ptr = NULL;
	int res;
	size_t len;
	u8 flags;
	bool server_msk, server_emsk;

	if (eap_teapv2_validate_crypto_binding(data, cb) < 0 ||
	    eap_teapv2_get_cmk(sm, data, cmk_msk, cmk_emsk) < 0)
		return NULL;

	/* Validate received MSK/EMSK Compound MAC */
	flags = cb->subtype >> 4;
	server_msk = flags == TEAPV2_CRYPTO_BINDING_MSK_CMAC ||
		flags == TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC;
	server_emsk = flags == TEAPV2_CRYPTO_BINDING_EMSK_CMAC ||
		flags == TEAPV2_CRYPTO_BINDING_EMSK_AND_MSK_CMAC;

	if (server_msk) {
		u8 msk_compound_mac[EAP_TEAPV2_COMPOUND_MAC_LEN];

		if (eap_teapv2_compound_mac(data->tls_cs, cb,
					  data->server_outer_tlvs,
					  data->peer_outer_tlvs, cmk_msk,
					  msk_compound_mac) < 0)
			return NULL;
		res = os_memcmp_const(msk_compound_mac, cb->msk_compound_mac,
				      EAP_TEAPV2_COMPOUND_MAC_LEN);
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Received MSK Compound MAC",
			    cb->msk_compound_mac, EAP_TEAPV2_COMPOUND_MAC_LEN);
		wpa_hexdump(MSG_MSGDUMP,
			    "EAP-TEAPV2: Calculated MSK Compound MAC",
			    msk_compound_mac, EAP_TEAPV2_COMPOUND_MAC_LEN);
		if (res != 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: MSK Compound MAC did not match");
			return NULL;
		}
	}

	if (server_emsk && data->cmk_emsk_available) {
		u8 emsk_compound_mac[EAP_TEAPV2_COMPOUND_MAC_LEN];

		if (eap_teapv2_compound_mac(data->tls_cs, cb,
					  data->server_outer_tlvs,
					  data->peer_outer_tlvs, cmk_emsk,
					  emsk_compound_mac) < 0)
			return NULL;
		res = os_memcmp_const(emsk_compound_mac, cb->emsk_compound_mac,
				      EAP_TEAPV2_COMPOUND_MAC_LEN);
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Received EMSK Compound MAC",
			    cb->emsk_compound_mac, EAP_TEAPV2_COMPOUND_MAC_LEN);
		wpa_hexdump(MSG_MSGDUMP,
			    "EAP-TEAPV2: Calculated EMSK Compound MAC",
			    emsk_compound_mac, EAP_TEAPV2_COMPOUND_MAC_LEN);
		if (res != 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: EMSK Compound MAC did not match");
			return NULL;
		}
	}

	if (flags == TEAPV2_CRYPTO_BINDING_EMSK_CMAC &&
	    !data->cmk_emsk_available) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Server included only EMSK Compound MAC, but no locally generated inner EAP EMSK to validate this");
		return NULL;
	}

	/*
	 * Compound MAC was valid, so authentication succeeded. Reply with
	 * crypto binding to allow server to complete authentication.
	 */

	if (server_emsk && data->cmk_emsk_available) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Selected S-IMCK_EMSK");
		os_memcpy(data->simck, data->simck_emsk, EAP_TEAPV2_SIMCK_LEN);
		cmk_emsk_ptr = cmk_emsk;
	} else if (server_msk) {
		wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Selected S-IMCK_MSK");
		os_memcpy(data->simck, data->simck_msk, EAP_TEAPV2_SIMCK_LEN);
		cmk_msk_ptr = cmk_msk;
	} else {
		return NULL;
	}
	wpa_hexdump_key(MSG_DEBUG, "EAP-TEAPV2: Selected S-IMCK[j]",
			data->simck, EAP_TEAPV2_SIMCK_LEN);

	len = sizeof(struct teapv2_tlv_crypto_binding);
	resp = wpabuf_alloc(len);
	if (!resp)
		return NULL;

	if (data->phase2_success && eap_teapv2_derive_msk(data) < 0) {
		wpa_printf(MSG_INFO, "EAP-TEAPV2: Failed to generate MSK");
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		data->phase2_success = 0;
		wpabuf_free(resp);
		return NULL;
	}

	if (data->phase2_success && eap_teapv2_session_id(data) < 0) {
		wpabuf_free(resp);
		return NULL;
	}

	pos = wpabuf_put(resp, sizeof(struct teapv2_tlv_crypto_binding));
	if (eap_teapv2_write_crypto_binding(
		    data, (struct teapv2_tlv_crypto_binding *) pos,
		    cb, cmk_msk_ptr, cmk_emsk_ptr) < 0) {
		wpabuf_free(resp);
		return NULL;
	}

	return resp;
}


static int eap_teapv2_parse_decrypted(struct wpabuf *decrypted,
				    struct eap_teapv2_tlv_parse *tlv,
				    struct wpabuf **resp)
{
	u16 tlv_type;
	int mandatory, res;
	size_t len;
	u8 *pos, *end;

	os_memset(tlv, 0, sizeof(*tlv));

	/* Parse TLVs from the decrypted Phase 2 data */
	pos = wpabuf_mhead(decrypted);
	end = pos + wpabuf_len(decrypted);
	while (end - pos >= 4) {
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
				*resp = eap_teapv2_tlv_nak(0, tlv_type);
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


static int eap_teapv2_process_decrypted(struct eap_sm *sm,
				      struct eap_teapv2_data *data,
				      struct eap_method_ret *ret,
				      u8 identifier,
				      struct wpabuf *decrypted,
				      struct wpabuf **out_data)
{
	struct wpabuf *resp = NULL, *tmp;
	struct eap_teapv2_tlv_parse tlv;
	int failed = 0;
	enum teapv2_error_codes error = 0;
	int iresult_added = 0;
	bool expect_crypto_binding = data->inner_method_done &&
		data->phase2_success;

	if (eap_teapv2_parse_decrypted(decrypted, &tlv, &resp) < 0) {
		/* Parsing failed - no response available */
		return 0;
	}

	if (resp) {
		/* Parsing rejected the message - send out an error response */
		goto send_resp;
	}

	if (tlv.trusted_server_root)
		eap_teapv2_process_trusted_server_root(
			sm, tlv.trusted_server_root,
			tlv.trusted_server_root_len);

	if (tlv.result == TEAPV2_STATUS_FAILURE) {
		/* Server indicated failure - respond similarly per
		 * RFC 7170, 3.6.3. This authentication exchange cannot succeed
		 * and will be terminated with a cleartext EAP Failure. */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Server rejected authentication");
		resp = eap_teapv2_tlv_result(TEAPV2_STATUS_FAILURE, 0);
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		goto send_resp;
	}

	if (data->cb_required && expect_crypto_binding &&
	    tlv.iresult == TEAPV2_STATUS_SUCCESS && !tlv.crypto_binding) {
		/* Intermediate-Result TLV indicating success, but no
		 * Crypto-Binding TLV */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Intermediate-Result TLV indicating success, but no Crypto-Binding TLV");
		failed = 1;
		error = TEAPV2_ERROR_TUNNEL_COMPROMISE_ERROR;
		goto done;
	}

	if (data->cb_required && expect_crypto_binding &&
	    !data->iresult_verified &&
	    !data->result_success_done &&
	    tlv.result == TEAPV2_STATUS_SUCCESS && !tlv.crypto_binding) {
		/* Result TLV indicating success, but no Crypto-Binding TLV */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Result TLV indicating success, but no Crypto-Binding TLV");
		failed = 1;
		error = TEAPV2_ERROR_TUNNEL_COMPROMISE_ERROR;
		goto done;
	}

	if (tlv.iresult != TEAPV2_STATUS_SUCCESS &&
	    tlv.iresult != TEAPV2_STATUS_FAILURE &&
	    data->inner_method_done) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Inner EAP method exchange completed, but no Intermediate-Result TLV included");
		failed = 1;
		error = TEAPV2_ERROR_TUNNEL_COMPROMISE_ERROR;
		goto done;
	}

	if (tlv.crypto_binding) {
		if (tlv.iresult != TEAPV2_STATUS_SUCCESS &&
		    tlv.result != TEAPV2_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Unexpected Crypto-Binding TLV without Result TLV or Intermediate-Result TLV indicating success");
			failed = 1;
			error = TEAPV2_ERROR_UNEXPECTED_TLVS_EXCHANGED;
			goto done;
		}

		tmp = eap_teapv2_process_crypto_binding(sm, data, ret,
						      tlv.crypto_binding,
						      tlv.crypto_binding_len);
		if (!tmp) {
			failed = 1;
			error = TEAPV2_ERROR_TUNNEL_COMPROMISE_ERROR;
		} else {
			resp = wpabuf_concat(resp, tmp);
			if (tlv.result == TEAPV2_STATUS_SUCCESS && !failed)
				data->result_success_done = 1;
			if (tlv.iresult == TEAPV2_STATUS_SUCCESS && !failed) {
				data->inner_method_done = 0;
				data->iresult_verified = 1;
			}
		}
	} else if (data->inner_method_done) {
		data->inner_method_done = 0;
	}

	if (tlv.identity_type == TEAPV2_IDENTITY_TYPE_MACHINE) {
		struct eap_peer_config *config = eap_get_config(sm);

		sm->use_machine_cred = config && config->machine_identity &&
			config->machine_identity_len;
	} else if (tlv.identity_type) {
		sm->use_machine_cred = 0;
	}
	if (tlv.identity_type) {
		struct eap_peer_config *config = eap_get_config(sm);

		os_free(data->phase2_types);
		data->phase2_types = NULL;
		data->num_phase2_types = 0;
		if (config &&
		    eap_peer_select_phase2_methods(config, "auth=",
						   &data->phase2_types,
						   &data->num_phase2_types,
						   sm->use_machine_cred) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to update Phase 2 EAP types");
			failed = 1;
			goto done;
		}
	}

	if (tlv.csr_attrs) {
		wpabuf_free(data->csr_attrs);
		data->csr_attrs = wpabuf_alloc_copy(tlv.csr_attrs,
						    tlv.csr_attrs_len);
		if (!data->csr_attrs) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to store CSR Attributes TLV");
			failed = 1;
			goto done;
		}
	}

	if (tlv.request_action == TEAPV2_REQUEST_ACTION_PROCESS_TLV &&
	    tlv.request_action_tlvs_type == TEAPV2_TLV_PKCS10) {
		struct eap_peer_config *config = eap_get_config(sm);

		if (config && config->teapv2_ignore_request_action_pkcs10) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Ignoring Request-Action for PKCS#10 CSR");
		} else {
			wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Generating PKCS#10 response");
			tmp = eap_teapv2_build_pkcs10_tlv(sm, data);
			if (!tmp) {
				wpa_printf(MSG_INFO,
					"EAP-TEAPV2: Failed to build PKCS#10 TLV");
				failed = 1;
				goto done;
			}
			resp = wpabuf_concat(resp, tmp);
			goto send_resp;
		}
	}

	if (tlv.pkcs7) {
		if (eap_teapv2_process_pkcs7(sm, data, tlv.pkcs7, tlv.pkcs7_len) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to store PKCS#7 certificate");
		failed = 1;
		goto done;
		}

		data->pkcs7_success = true;
		if (eap_teapv2_derive_msk(data) < 0 ||
		    eap_teapv2_session_id(data) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to derive keys after PKCS#7");
			failed = 1;
			goto done;
		}
	}

	if (tlv.basic_auth_req) {
		tmp = eap_teapv2_process_basic_auth_req(sm, data,
						      tlv.basic_auth_req,
						      tlv.basic_auth_req_len,
						      tlv.identity_type);
		if (!tmp)
			failed = 1;
		else if (eap_teapv2_derive_msk(data) < 0 ||
			 	 eap_teapv2_session_id(data) < 0) {
				wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Failed to derive keys after basic auth");
				failed = 1;
				goto done;
				}
		resp = wpabuf_concat(resp, tmp);
	} else if (tlv.eap_payload_tlv) {
		tmp = eap_teapv2_process_eap_payload_tlv(sm, data, ret,
						       tlv.eap_payload_tlv,
						       tlv.eap_payload_tlv_len,
						       tlv.identity_type);
		if (!tmp)
			failed = 1;
		resp = wpabuf_concat(resp, tmp);

		if (tlv.iresult == TEAPV2_STATUS_SUCCESS ||
		    tlv.iresult == TEAPV2_STATUS_FAILURE) {
			tmp = eap_teapv2_tlv_result(failed ?
						  TEAPV2_STATUS_FAILURE :
						  TEAPV2_STATUS_SUCCESS, 1);
			resp = wpabuf_concat(resp, tmp);
			if (tlv.iresult == TEAPV2_STATUS_FAILURE)
				failed = 1;
			iresult_added = 1;
		}
	}

	if ((data->result_success_done || (!expect_crypto_binding && tlv.result == TEAPV2_STATUS_SUCCESS)) &&
	    tls_connection_get_own_cert_used(data->ssl.conn) &&
	    eap_teapv2_derive_msk(data) == 0) {
		/* Assume the server might accept authentication without going
		 * through inner authentication. */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Client certificate used - server may decide to skip inner authentication");
		data->client_authenticated = true;
		ret->methodState = METHOD_MAY_CONT;
		ret->decision = DECISION_COND_SUCC;
	}

done:
	if (failed) {
		tmp = eap_teapv2_tlv_result(TEAPV2_STATUS_FAILURE, 0);
		resp = wpabuf_concat(tmp, resp);

		if (error != 0) {
			tmp = eap_teapv2_tlv_error(error);
			resp = wpabuf_concat(tmp, resp);
		}

		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
	} else if (tlv.result == TEAPV2_STATUS_SUCCESS) {
		tmp = eap_teapv2_tlv_result(TEAPV2_STATUS_SUCCESS, 0);
		resp = wpabuf_concat(tmp, resp);
	}
	if ((tlv.iresult == TEAPV2_STATUS_SUCCESS ||
	     tlv.iresult == TEAPV2_STATUS_FAILURE) && !iresult_added) {
		tmp = eap_teapv2_tlv_result((!failed && data->phase2_success) ?
					  TEAPV2_STATUS_SUCCESS :
					  TEAPV2_STATUS_FAILURE, 1);
		if (tlv.iresult == TEAPV2_STATUS_FAILURE)
			wpa_printf(MSG_ERROR, "TEAPV2: Intermediate status = FAIL");
		resp = wpabuf_concat(tmp, resp);
	}

	if (resp && ((tlv.result == TEAPV2_STATUS_SUCCESS && !failed &&
	    (tlv.crypto_binding || data->iresult_verified ||
	     !data->cb_required) &&
	    data->phase2_success) || (data->pkcs7_success || data->client_authenticated))) {
		/* Successfully completed Phase 2 */
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Authentication completed successfully");
		ret->methodState = METHOD_MAY_CONT;
		data->on_tx_completion = METHOD_DONE;
		ret->decision = DECISION_UNCOND_SUCC;
		if (! data->cb_required ) {
			if (eap_teapv2_derive_msk(data) < 0 ||
					eap_teapv2_session_id(data) < 0) {
					wpa_printf(MSG_INFO,
					"EAP-TEAPV2: Failed to derive keys");
					failed = 1;
					goto done;
					}
		}
	}

	if (!resp) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: No recognized TLVs - send empty response packet");
		resp = wpabuf_alloc(1);
	}

send_resp:
	if (!resp)
		return 0;

	wpa_hexdump_buf(MSG_DEBUG, "EAP-TEAPV2: Encrypting Phase 2 data", resp);
	if (eap_peer_tls_encrypt(sm, &data->ssl, EAP_TYPE_TEAPV2,
				 data->teapv2_version, identifier,
				 resp, out_data)) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Failed to encrypt a Phase 2 frame");
	}
	wpabuf_free(resp);

	return 0;
}


static int eap_teapv2_decrypt(struct eap_sm *sm, struct eap_teapv2_data *data,
			    struct eap_method_ret *ret, u8 identifier,
			    const struct wpabuf *in_data,
			    struct wpabuf **out_data)
{
	struct wpabuf *in_decrypted;
	int res;

	wpa_printf(MSG_DEBUG,
		   "EAP-TEAPV2: Received %lu bytes encrypted data for Phase 2",
		   (unsigned long) wpabuf_len(in_data));

	if (data->pending_phase2_req) {
		wpa_printf(MSG_DEBUG,
			   "EAP-TEAPV2: Pending Phase 2 request - skip decryption and use old data");
		/* Clear TLS reassembly state. */
		eap_peer_tls_reset_input(&data->ssl);

		in_decrypted = data->pending_phase2_req;
		data->pending_phase2_req = NULL;
		goto continue_req;
	}

	if (wpabuf_len(in_data) == 0) {
		/* Received TLS ACK - requesting more fragments */
		res = eap_peer_tls_encrypt(sm, &data->ssl, EAP_TYPE_TEAPV2,
					   data->teapv2_version,
					   identifier, NULL, out_data);
		if (res == 0 && !data->ssl.tls_out &&
		    data->on_tx_completion) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Mark authentication completed at full TX of fragments");
			ret->methodState = data->on_tx_completion;
			data->on_tx_completion = 0;
			ret->decision = DECISION_UNCOND_SUCC;
		}
		return res;
	}

	res = eap_peer_tls_decrypt(sm, &data->ssl, in_data, &in_decrypted);
	if (res)
		return res;

continue_req:
	wpa_hexdump_buf(MSG_MSGDUMP, "EAP-TEAPV2: Decrypted Phase 2 TLV(s)",
			in_decrypted);

	if (wpabuf_len(in_decrypted) < 4) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Too short Phase 2 TLV frame (len=%lu)",
			   (unsigned long) wpabuf_len(in_decrypted));
		wpabuf_free(in_decrypted);
		return -1;
	}

	res = eap_teapv2_process_decrypted(sm, data, ret, identifier,
					 in_decrypted, out_data);

	wpabuf_free(in_decrypted);

	return res;
}


static int eap_teapv2_process_start(struct eap_sm *sm,
				  struct eap_teapv2_data *data, u8 flags,
				  const u8 *pos, size_t left)
{
	const u8 *a_id = NULL;

	/* TODO: Support (mostly theoretical) case of TEAPV2/Start request being
	 * fragmented */

	/* EAP-TEAPV2 version negotiation (RFC 7170, Section 3.2) */
	data->received_version = flags & EAP_TLS_VERSION_MASK;
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Start (server ver=%u, own ver=%u)",
		   data->received_version, data->teapv2_version);
	if (data->received_version < 1) {
		/* Version 1 was the first defined version, so reject 0 */
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Server used unknown TEAPV2 version %u",
			   data->received_version);
		return -1;
	}
	if (data->received_version < data->teapv2_version)
		data->teapv2_version = data->received_version;
	wpa_printf(MSG_DEBUG, "EAP-TEAPV2: Using TEAPV2 version %d",
		   data->teapv2_version);
	wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Start message payload", pos, left);

	/* Parse Authority-ID TLV from Outer TLVs, if present */
	if (flags & EAP_TEAPV2_FLAGS_OUTER_TLV_LEN) {
		const u8 *outer_pos, *outer_end;
		u32 outer_tlv_len;

		if (left < 4) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Not enough room for the Outer TLV Length field");
			return -1;
		}

		outer_tlv_len = WPA_GET_BE32(pos);
		pos += 4;
		left -= 4;

		if (outer_tlv_len > left) {
			wpa_printf(MSG_INFO,
				   "EAP-TEAPV2: Truncated Outer TLVs field (Outer TLV Length: %u; remaining buffer: %u)",
				   outer_tlv_len, (unsigned int) left);
			return -1;
		}

		outer_pos = pos + left - outer_tlv_len;
		outer_end = outer_pos + outer_tlv_len;
		wpa_hexdump(MSG_MSGDUMP, "EAP-TEAPV2: Start message Outer TLVs",
			    outer_pos, outer_tlv_len);
		wpabuf_free(data->server_outer_tlvs);
		data->server_outer_tlvs = wpabuf_alloc_copy(outer_pos,
							    outer_tlv_len);
		if (!data->server_outer_tlvs)
			return -1;
		left -= outer_tlv_len;
		if (left > 0) {
			wpa_hexdump(MSG_INFO,
				    "EAP-TEAPV2: Unexpected TLS Data in Start message",
				    pos, left);
			return -1;
		}

		while (outer_pos < outer_end) {
			u16 tlv_type, tlv_len;

			if (outer_end - outer_pos < 4) {
				wpa_printf(MSG_INFO,
					   "EAP-TEAPV2: Truncated Outer TLV header");
				return -1;
			}
			tlv_type = WPA_GET_BE16(outer_pos);
			outer_pos += 2;
			tlv_len = WPA_GET_BE16(outer_pos);
			outer_pos += 2;
			/* Outer TLVs are required to be optional, so no need to
			 * check the M flag */
			tlv_type &= TEAPV2_TLV_TYPE_MASK;
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Outer TLV: Type=%u Length=%u",
				   tlv_type, tlv_len);
			if (outer_end - outer_pos < tlv_len) {
				wpa_printf(MSG_INFO,
					   "EAP-TEAPV2: Truncated Outer TLV (Type %u)",
					   tlv_type);
				return -1;
			}
			if (tlv_type == TEAPV2_TLV_AUTHORITY_ID) {
				wpa_hexdump(MSG_DEBUG, "EAP-TEAPV2: Authority-ID",
					    outer_pos, tlv_len);
				if (a_id) {
					wpa_printf(MSG_INFO,
						   "EAP-TEAPV2: Multiple Authority-ID TLVs in TEAPV2/Start");
					return -1;
				}
				a_id = outer_pos;
			} else {
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: Ignore unknown Outer TLV (Type %u)",
					   tlv_type);
			}
			outer_pos += tlv_len;
		}
	} else if (left > 0) {
		wpa_hexdump(MSG_INFO,
			    "EAP-TEAPV2: Unexpected TLS Data in Start message",
			    pos, left);
		return -1;
	}

	return 0;
}


#ifdef CONFIG_TESTING_OPTIONS
static struct wpabuf * eap_teapv2_add_stub_outer_tlvs(struct eap_teapv2_data *data,
						    struct wpabuf *resp)
{
	struct wpabuf *resp2;
	u16 len;
	const u8 *pos;
	u8 flags;

	wpabuf_free(data->peer_outer_tlvs);
	data->peer_outer_tlvs = wpabuf_alloc(4 + 4);
	if (!data->peer_outer_tlvs) {
		wpabuf_free(resp);
		return NULL;
	}

	/* Outer TLVs (stub Vendor-Specific TLV for testing) */
	wpabuf_put_be16(data->peer_outer_tlvs, TEAPV2_TLV_VENDOR_SPECIFIC);
	wpabuf_put_be16(data->peer_outer_tlvs, 4);
	wpabuf_put_be32(data->peer_outer_tlvs, EAP_VENDOR_HOSTAP);
	wpa_hexdump_buf(MSG_DEBUG, "EAP-TEAPV2: TESTING - Add stub Outer TLVs",
			data->peer_outer_tlvs);

	wpa_hexdump_buf(MSG_DEBUG,
			"EAP-TEAPV2: TEAPV2/Start response before modification",
			resp);
	resp2 = wpabuf_alloc(wpabuf_len(resp) + 4 +
			     wpabuf_len(data->peer_outer_tlvs));
	if (!resp2) {
		wpabuf_free(resp);
		return NULL;
	}

	pos = wpabuf_head(resp);
	wpabuf_put_u8(resp2, *pos++); /* Code */
	wpabuf_put_u8(resp2, *pos++); /* Identifier */
	len = WPA_GET_BE16(pos);
	pos += 2;
	wpabuf_put_be16(resp2, len + 4 + wpabuf_len(data->peer_outer_tlvs));
	wpabuf_put_u8(resp2, *pos++); /* Type */
	/* Flags | Ver (with Outer TLV length included flag set to 1) */
	flags = *pos++;
	if (flags & (EAP_TEAPV2_FLAGS_OUTER_TLV_LEN |
		     EAP_TLS_FLAGS_LENGTH_INCLUDED)) {
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Cannot add Outer TLVs for testing");
		wpabuf_free(resp);
		wpabuf_free(resp2);
		return NULL;
	}
	flags |= EAP_TEAPV2_FLAGS_OUTER_TLV_LEN;
	wpabuf_put_u8(resp2, flags);
	/* Outer TLV Length */
	wpabuf_put_be32(resp2, wpabuf_len(data->peer_outer_tlvs));
	/* TLS Data */
	wpabuf_put_data(resp2, pos, wpabuf_len(resp) - 6);
	wpabuf_put_buf(resp2, data->peer_outer_tlvs); /* Outer TLVs */

	wpabuf_free(resp);
	wpa_hexdump_buf(MSG_DEBUG,
			"EAP-TEAPV2: TEAPV2/Start response after modification",
			resp2);
	return resp2;
}
#endif /* CONFIG_TESTING_OPTIONS */


static struct wpabuf * eap_teapv2_process(struct eap_sm *sm, void *priv,
					struct eap_method_ret *ret,
					const struct wpabuf *reqData)
{
	const struct eap_hdr *req;
	size_t left;
	int res;
	u8 flags, id;
	struct wpabuf *resp;
	const u8 *pos;
	struct eap_teapv2_data *data = priv;
	struct wpabuf msg;

	pos = eap_peer_tls_process_init(sm, &data->ssl, EAP_TYPE_TEAPV2, ret,
					reqData, &left, &flags);
	if (!pos)
		return NULL;

	req = wpabuf_head(reqData);
	id = req->identifier;

	if (flags & EAP_TLS_FLAGS_START) {
		if (eap_teapv2_process_start(sm, data, flags, pos, left) < 0)
			return NULL;

		/* Outer TLVs are not used in further packet processing and
		 * there cannot be TLS Data in this TEAPV2/Start message, so
		 * enforce that by ignoring whatever data might remain in the
		 * buffer. */
		left = 0;
	} else if (flags & EAP_TEAPV2_FLAGS_OUTER_TLV_LEN) {
		/* TODO: RFC 7170, Section 4.3.1 indicates that the unexpected
		 * Outer TLVs MUST be ignored instead of ignoring the full
		 * message. */
		wpa_printf(MSG_INFO,
			   "EAP-TEAPV2: Outer TLVs present in non-Start message -> ignore message");
		return NULL;
	}

	wpabuf_set(&msg, pos, left);

	resp = NULL;
	if (tls_connection_established(sm->ssl_ctx, data->ssl.conn) &&
	    !data->resuming) {
		/* Process tunneled (encrypted) phase 2 data. */
		res = eap_teapv2_decrypt(sm, data, ret, id, &msg, &resp);
		if (res < 0) {
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			/*
			 * Ack possible Alert that may have caused failure in
			 * decryption.
			 */
			res = 1;
		}
	} else {
		if (sm->waiting_ext_cert_check && data->pending_resp) {
			struct eap_peer_config *config = eap_get_config(sm);

			if (config->pending_ext_cert_check ==
			    EXT_CERT_CHECK_GOOD) {
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: External certificate check succeeded - continue handshake");
				resp = data->pending_resp;
				data->pending_resp = NULL;
				sm->waiting_ext_cert_check = 0;
				return resp;
			}

			if (config->pending_ext_cert_check ==
			    EXT_CERT_CHECK_BAD) {
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: External certificate check failed - force authentication failure");
				ret->methodState = METHOD_DONE;
				ret->decision = DECISION_FAIL;
				sm->waiting_ext_cert_check = 0;
				return NULL;
			}

			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Continuing to wait external server certificate validation");
			return NULL;
		}

		/* Continue processing TLS handshake (phase 1). */
		res = eap_peer_tls_process_helper(sm, &data->ssl,
						  EAP_TYPE_TEAPV2,
						  data->teapv2_version, id, &msg,
						  &resp);
		if (res < 0) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: TLS processing failed");
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			return resp;
		}

		if (sm->waiting_ext_cert_check) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: Waiting external server certificate validation");
			wpabuf_free(data->pending_resp);
			data->pending_resp = resp;
			return NULL;
		}

		if (tls_connection_established(sm->ssl_ctx, data->ssl.conn)) {
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: TLS done, proceed to Phase 2");
			data->tls_cs =
				tls_connection_get_cipher_suite(data->ssl.conn);
			wpa_printf(MSG_DEBUG,
				   "EAP-TEAPV2: TLS cipher suite 0x%04x",
				   data->tls_cs);

			data->resuming = 0;
			if (eap_teapv2_derive_key_auth(sm, data) < 0) {
				wpa_printf(MSG_DEBUG,
					   "EAP-TEAPV2: Could not derive keys");
				ret->methodState = METHOD_DONE;
				ret->decision = DECISION_FAIL;
				wpabuf_free(resp);
				return NULL;
			}
		}

		if (res == 2) {
			/*
			 * Application data included in the handshake message.
			 */
			wpabuf_free(data->pending_phase2_req);
			data->pending_phase2_req = resp;
			resp = NULL;
			res = eap_teapv2_decrypt(sm, data, ret, id, &msg, &resp);
		}
	}

	if (res == 1) {
		wpabuf_free(resp);
		return eap_peer_tls_build_ack(id, EAP_TYPE_TEAPV2,
					      data->teapv2_version);
	}

#ifdef CONFIG_TESTING_OPTIONS
	if (data->test_outer_tlvs && res == 0 && resp &&
	    (flags & EAP_TLS_FLAGS_START) && wpabuf_len(resp) >= 6)
		resp = eap_teapv2_add_stub_outer_tlvs(data, resp);
#endif /* CONFIG_TESTING_OPTIONS */

	return resp;
}


#if 0 /* TODO */
static bool eap_teapv2_has_reauth_data(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	return tls_connection_established(sm->ssl_ctx, data->ssl.conn);
}


static void eap_teapv2_deinit_for_reauth(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	if (data->phase2_priv && data->phase2_method &&
	    data->phase2_method->deinit_for_reauth)
		data->phase2_method->deinit_for_reauth(sm, data->phase2_priv);
	eap_teapv2_clear(data);
}


static void * eap_teapv2_init_for_reauth(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	if (eap_peer_tls_reauth_init(sm, &data->ssl)) {
		eap_teapv2_deinit(sm, data);
		return NULL;
	}
	if (data->phase2_priv && data->phase2_method &&
	    data->phase2_method->init_for_reauth)
		data->phase2_method->init_for_reauth(sm, data->phase2_priv);
	data->phase2_success = 0;
	data->inner_method_done = 0;
	data->result_success_done = 0;
	data->iresult_verified = 0;
	data->pkcs7_success = false;
	data->done_on_tx_completion = 0;
	data->resuming = 1;
	data->simck_idx = 0;
	return priv;
}
#endif


static int eap_teapv2_get_status(struct eap_sm *sm, void *priv, char *buf,
			       size_t buflen, int verbose)
{
	struct eap_teapv2_data *data = priv;
	int len, ret;

	len = eap_peer_tls_status(sm, &data->ssl, buf, buflen, verbose);
	if (data->phase2_method) {
		ret = os_snprintf(buf + len, buflen - len,
				  "EAP-TEAPV2 Phase 2 method=%s\n",
				  data->phase2_method->name);
		if (os_snprintf_error(buflen - len, ret))
			return len;
		len += ret;
	}
	return len;
}


static bool eap_teapv2_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_teapv2_data *data = priv;

	return data->success;
}


static u8 * eap_teapv2_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_teapv2_data *data = priv;
	u8 *key;

	if (!data->success)
		return NULL;

	key = os_memdup(data->key_data, EAP_TEAPV2_KEY_LEN);
	if (!key)
		return NULL;

	*len = EAP_TEAPV2_KEY_LEN;

	return key;
}


static u8 * eap_teapv2_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_teapv2_data *data = priv;
	u8 *id;

	if (!data->success || !data->session_id)
		return NULL;

	id = os_memdup(data->session_id, data->id_len);
	if (!id)
		return NULL;

	*len = data->id_len;

	return id;
}


static u8 * eap_teapv2_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_teapv2_data *data = priv;
	u8 *key;

	if (!data->success)
		return NULL;

	key = os_memdup(data->emsk, EAP_EMSK_LEN);
	if (!key)
		return NULL;

	*len = EAP_EMSK_LEN;

	return key;
}


int eap_peer_teapv2_register(void)
{
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_TEAPV2, "TEAPV2");
	if (!eap)
		return -1;

	eap->init = eap_teapv2_init;
	eap->deinit = eap_teapv2_deinit;
	eap->process = eap_teapv2_process;
	eap->isKeyAvailable = eap_teapv2_isKeyAvailable;
	eap->getKey = eap_teapv2_getKey;
	eap->getSessionId = eap_teapv2_get_session_id;
	eap->get_status = eap_teapv2_get_status;
#if 0 /* TODO */
	eap->has_reauth_data = eap_teapv2_has_reauth_data;
	eap->deinit_for_reauth = eap_teapv2_deinit_for_reauth;
	eap->init_for_reauth = eap_teapv2_init_for_reauth;
#endif
	eap->get_emsk = eap_teapv2_get_emsk;

	return eap_peer_method_register(eap);
}
