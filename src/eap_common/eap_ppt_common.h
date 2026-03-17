/*
 * EAP-PPT: EAP using Privacy Pass Token (draft-ietf-emu-eap-ppt)
 * Shared definitions for peer and server
 *
 * Copyright (c) 2024, The hostap Project
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_PPT_COMMON_H
#define EAP_PPT_COMMON_H

/* EAP-PPT type value (draft-ietf-emu-eap-ppt, pending IANA assignment) */
#define EAP_TYPE_PPT_VAL 57

/* EAP-PPT Subtypes */
#define EAP_PPT_SUBTYPE_CHALLENGE       1
#define EAP_PPT_SUBTYPE_ERROR           2
#define EAP_PPT_SUBTYPE_CHANNEL_BINDING 3

/* EAP-PPT Error Codes (Section 5.3 of draft-ietf-emu-eap-ppt) */
#define EAP_PPT_ERROR_GENERIC           1
#define EAP_PPT_ERROR_BAD_TOKEN         2
#define EAP_PPT_ERROR_EXPIRED_TOKEN     3
#define EAP_PPT_ERROR_UNKNOWN_ISSUER    4
#define EAP_PPT_ERROR_UNKNOWN_TYPE      5
#define EAP_PPT_ERROR_ALREADY_REDEEMED 6
#define EAP_PPT_ERROR_BAD_CHANNEL_BIND  7
#define EAP_PPT_ERROR_UNSPECIFIED       8

/* TLS exporter label for key material derivation (Section 6.6) */
#define EAP_PPT_TLS_EXPORTER_LABEL "EXPORTER_EAP_PPT_Key_Material"

/* Key material total length: 64 bytes MSK + 64 bytes EMSK */
#define EAP_PPT_KEY_MATERIAL_LEN 128
#define EAP_PPT_MSK_LEN  64
#define EAP_PPT_EMSK_LEN 64

/* Packet header: EAP header (4) + Type (1) + Subtype (1) */
#define EAP_PPT_HDR_LEN 2  /* Just the Type+Subtype beyond eap_hdr */

/* JSON field name constants */
#define EAP_PPT_JSON_CHALLENGES        "challenges"
#define EAP_PPT_JSON_CHALLENGE         "challenge"
#define EAP_PPT_JSON_TOKEN_KEY         "token-key"
#define EAP_PPT_JSON_EXTENSION_TYPES   "extension-types"
#define EAP_PPT_JSON_TOKEN             "token"
#define EAP_PPT_JSON_EXTENSIONS        "extensions"
#define EAP_PPT_JSON_CODE              "code"
#define EAP_PPT_JSON_DESCRIPTION       "description"
#define EAP_PPT_JSON_SESSION_TIMEOUT   "session-timeout"

/*
 * Privacy Pass Token Types (RFC 9576)
 *   0x0001 = VOPRF (ristretto255, SHA-512)
 *   0x0002 = Blind RSA (SHA-384, 2048-bit)
 */
#define EAP_PPT_TOKEN_TYPE_VOPRF    0x0001
#define EAP_PPT_TOKEN_TYPE_BLIND_RSA 0x0002

#endif /* EAP_PPT_COMMON_H */
