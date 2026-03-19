# TEAPv2 Error Inventory

Each row represents one distinct error condition. The **File** and **Function** columns repeat for every error a function can produce.

---

## `eap_teapv2_common.c`

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2_common.c` | `eap_teapv2_tlv_eap_payload()` | 59 | Memory allocation failure for EAP-Payload TLV encapsulation buffer |
| `eap_teapv2_common.c` | `eap_teapv2_tls_mac()` | 312 | Unsupported TLS cipher suite (not SHA-1, SHA-256, or SHA-384) |
| `eap_teapv2_common.c` | `eap_teapv2_derive_eap_msk()` | 96 | tls_prf failure during MSK derivation |
| `eap_teapv2_common.c` | `eap_teapv2_derive_eap_emsk()` | 114 | tls_prf failure during EMSK derivation |
| `eap_teapv2_common.c` | `eap_teapv2_derive_imck()` | 158 | tls_prf failure — EMSK path: IMSK derivation |
| `eap_teapv2_common.c` | `eap_teapv2_derive_imck()` | 169 | tls_prf failure — EMSK path: IMCK derivation |
| `eap_teapv2_common.c` | `eap_teapv2_derive_imck()` | 199 | tls_prf failure — MSK path: IMCK derivation |
| `eap_teapv2_common.c` | `eap_teapv2_compound_mac()` | 346 | Memory allocation failure for MAC input buffer |
| `eap_teapv2_common.c` | `eap_teapv2_compound_mac()` | 388 | MAC calculation failure |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_IDENTITY_TYPE) | 403 | TLV length < 2 |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_RESULT) | 415 | More than one Result TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_RESULT) | 421 | TLV length < 2 |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_RESULT) | 428 | Unknown status value |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_NAK) | 439 | TLV length < 6 |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_ERROR) | 448 | TLV length < 4 |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_REQUEST_ACTION) | 459 | More than one Request-Action TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_REQUEST_ACTION) | 465 | TLV length < 2 |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_EAP_PAYLOAD) | 485 | More than one EAP-Payload TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_INTERMEDIATE_RESULT) | 497 | TLV length < 2 |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_INTERMEDIATE_RESULT) | 503 | More than one Intermediate-Result TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_INTERMEDIATE_RESULT) | 511 | Unknown status value |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_PAC) | 523 | More than one PAC TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_CRYPTO_BINDING) | 535 | More than one Crypto-Binding TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_CRYPTO_BINDING) | 542 | TLV too short to hold full struct |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_BASIC_PASSWORD_AUTH_REQ) | 555 | More than one Basic-Password-Auth-Req TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_BASIC_PASSWORD_AUTH_RESP) | 568 | More than one Basic-Password-Auth-Resp TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_PKCS7) | 578 | More than one PKCS#7 TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_PKCS10) | 589 | More than one PKCS#10 TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_TRUSTED_SERVER_ROOT) | 600 | More than one Trusted-Server-Root TLV |
| `eap_teapv2_common.c` | `eap_teapv2_parse_tlv()` (TEAPV2_TLV_CSR_ATTRS) | 612 | More than one CSR-Attributes TLV |

---

---

## `eap_server_teapv2.c` — Initialization

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_server_teapv2.c` | `eap_teapv2_load_trusted_server_root()` | 97 | File read failure |
| `eap_server_teapv2.c` | `eap_teapv2_load_trusted_server_root()` | 108 | No PEM end tag found |
| `eap_server_teapv2.c` | `eap_teapv2_load_trusted_server_root()` | 117 | Base64 decode failure |
| `eap_server_teapv2.c` | `eap_teapv2_load_csr_attrs()` | 145 | Base64 decode failure |
| `eap_server_teapv2.c` | `eap_teapv2_load_csr_attrs()` | 153 | DER is not a SEQUENCE, or has trailing bytes |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 344 | Memory allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 356 | SSL initialization failure |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 362 | No A-ID configured |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 369 | A-ID memory allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 376 | No A-ID-Info configured |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 383 | A-ID-Info strdup failure |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 392 | Trusted server root loading failure |
| `eap_server_teapv2.c` | `eap_teapv2_init()` | 401 | CSR attributes loading failure |

## `eap_server_teapv2.c` — Building Requests

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_server_teapv2.c` | `eap_teapv2_build_start()` | 446 | Message allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_build_start()` | 467 | server_outer_tlvs allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_phase1_done()` | 499 | eap_teapv2_derive_key_auth() failure (-> FAILURE state) |
| `eap_server_teapv2.c` | `eap_teapv2_add_request_action()` | 527 | Request-Action TLV allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_add_request_action()` | 543 | CSR-Attributes TLV allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_add_trusted_server_root()` | 570 | TLV allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_add_pkcs7()` | 592 | TLV allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_build_phase2_req()` | 656 | Phase 2 method not initialized |
| `eap_server_teapv2.c` | `eap_teapv2_build_phase2_req()` | 665 | buildReq returns NULL |
| `eap_server_teapv2.c` | `eap_teapv2_build_crypto_binding()` | 695 | random_get_bytes() failure |
| `eap_server_teapv2.c` | `eap_teapv2_build_crypto_binding()` | 712 | MSK Compound MAC calculation failure |
| `eap_server_teapv2.c` | `eap_teapv2_build_crypto_binding()` | 720 | EMSK Compound MAC calculation failure |
| `eap_server_teapv2.c` | `eap_teapv2_result_maybe_crypto_binding()` | 746 | Buffer allocation failure |
| `eap_server_teapv2.c` | `eap_teapv2_encrypt_phase2()` | 801 | TLS encryption failure |
| `eap_server_teapv2.c` | `eap_teapv2_encrypt_phase2()` | 810 | Output buffer resize failure |

## `eap_server_teapv2.c` — Processing Responses

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_server_teapv2.c` | `eap_teapv2_process_version()` | 1734 | Peer sent version 0 (only version >= 1 is valid) |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase1()` | 1757 | TLS handshake processing failure |
| `eap_server_teapv2.c` | `eap_teapv2_parse_tlvs()` | 1327 | TLV length exceeds remaining buffer (overflow) |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1381 | Version or received-version mismatch |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1388 | Flags not in range 1-3 |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1395 | Sub-type is not Response |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1405 | Nonce mismatch |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1425 | MSK Compound MAC mismatch |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1447 | EMSK Compound MAC mismatch |
| `eap_server_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1455 | Peer sent only EMSK MAC but no local EMSK was generated |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_eap()` | 1172 | Phase 2 EAP frame too short |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_eap()` | 1179 | EAP length field exceeds actual buffer |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_eap()` | 1195 | Unexpected EAP code (not Response) |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1034 | Phase 2 not initialized |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1051 | Peer NAK'd required TNC |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1072 | No further EAP methods available after NAK |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1080 | Phase 2 check() rejected the packet |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1092 | Inner method isSuccess() returned false |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1106 | Provided Identity-Type not allowed |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_response()` | 1113 | Identity not found in user database |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1213 | Identity-Type not allowed |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1224 | No room for Userlen field |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1231 | Truncated Username field |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1243 | No room for Passlen field |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1250 | Truncated Password field |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1262 | Unexpected trailing bytes after password |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1270 | Username not found in user database |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1277 | No plaintext password configured |
| `eap_server_teapv2.c` | `eap_teapv2_process_basic_auth_resp()` | 1285 | Password mismatch |
| `eap_server_teapv2.c` | `eap_teapv2_update_icmk()` | 303 | Phase 2 method/priv not available |
| `eap_server_teapv2.c` | `eap_teapv2_update_icmk()` | 311 | getKey returned NULL (MSK unavailable) |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1485 | TLV parsing failed |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1491 | Result TLV = Failure |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1497 | NAK TLV received |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1572 | Expected Crypto-Binding TLV missing |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1579 | Crypto-Binding received before inner EAP method completion |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1587 | Final-result Crypto-Binding present without Result=Success |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1596 | Non-basic-auth Crypto-Binding without Intermediate-Result=Success |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1610 | eap_teapv2_validate_crypto_binding() failure |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1635 | Unexpected Basic-Password-Auth-Resp when using inner EAP |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1647 | Unexpected EAP-Payload TLV when using Basic-Password-Auth |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2_tlvs()` | 1671 | Second-credential eap_teapv2_phase2_init() failure |
| `eap_server_teapv2.c` | `eap_teapv2_process_phase2()` | 1704 | TLS decryption failure (-> FAILURE state) |
| `eap_server_teapv2.c` | `eap_teapv2_process()` | 1897 | Outer TLVs present in non-first message |
| `eap_server_teapv2.c` | `eap_teapv2_process()` | 1913 | Message Length field too small to contain Outer TLV Length field |
| `eap_server_teapv2.c` | `eap_teapv2_process()` | 1920 | Message too short to include TLS data |
| `eap_server_teapv2.c` | `eap_teapv2_process()` | 1933 | Outer TLV length exceeds remaining buffer |
| `eap_server_teapv2.c` | `eap_teapv2_process()` | 1941 | Multiple Authority-ID TLVs in first message |
| `eap_server_teapv2.c` | `eap_teapv2_process()` | 1979 | TLS server processing failure |

## `eap_server_teapv2.c` — Key / Session Generation

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_server_teapv2.c` | `eap_teapv2_getKey()` | 2021 | eap_teapv2_derive_eap_msk() failure |
| `eap_server_teapv2.c` | `eap_teapv2_get_session_id()` | 2079 | tls_get_tls_unique() failure |

---

## `eap_server_teapv2.c` — Known Bug

> In `eap_teapv2_process_phase2_start()`, when `eap_teapv2_auth == 2` and the identity is already known, `eap_teapv2_derive_imck()` failure is not properly propagated — the function can only return `0` or `1` at that point, making the `-1` error path unreachable. There is a `// XXX` comment in the code acknowledging this.

---

## `eap_teapv2.c` — Initialization

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_init()` | 709 | No peer config available |
| `eap_teapv2.c` | `eap_teapv2_init()` | 713 | Memory allocation failure |
| `eap_teapv2.c` | `eap_teapv2_init()` | 723 | Phase 2 method selection failure |
| `eap_teapv2.c` | `eap_teapv2_init()` | 730 | SSL initialization failure |
| `eap_teapv2.c` | `eap_teapv2_store_blob()` | 102 | NULL argument(s) passed |
| `eap_teapv2.c` | `eap_teapv2_store_blob()` | 106 | Blob struct allocation failure |
| `eap_teapv2.c` | `eap_teapv2_store_blob()` | 115 | Blob name or data allocation failure |
| `eap_teapv2.c` | `eap_teapv2_store_blob()` | 124 | Name reference string allocation failure |

## `eap_teapv2.c` — Phase 1 / Start

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1874 | Server sent version 0 (only version >= 1 is valid) |
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1891 | Not enough room for Outer TLV Length field |
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1901 | Outer TLVs field truncated |
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1918 | Unexpected TLS data present after Outer TLVs |
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1928 | Outer TLV header truncated |
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1943 | Outer TLV body truncated |
| `eap_teapv2.c` | `eap_teapv2_process_start()` | 1952 | Multiple Authority-ID TLVs in Start message |
| `eap_teapv2.c` | `eap_teapv2_derive_key_auth()` | 803 | TLS key export failure |

## `eap_teapv2.c` — Crypto Binding

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1143 | Version, received-version, sub-type, or flags invalid |
| `eap_teapv2.c` | `eap_teapv2_validate_crypto_binding()` | 1150 | Nonce LSB is set in request (must be 0) |
| `eap_teapv2.c` | `eap_teapv2_write_crypto_binding()` | 1179 | Both cmk_msk and cmk_emsk are NULL |
| `eap_teapv2.c` | `eap_teapv2_write_crypto_binding()` | 1190 | MSK Compound MAC calculation failure |
| `eap_teapv2.c` | `eap_teapv2_write_crypto_binding()` | 1195 | EMSK Compound MAC calculation failure |
| `eap_teapv2.c` | `eap_teapv2_get_cmk()` | 1226 | Phase 2 method/priv not available |
| `eap_teapv2.c` | `eap_teapv2_get_cmk()` | 1232 | Phase 2 key material not available |
| `eap_teapv2.c` | `eap_teapv2_get_cmk()` | 1242 | MSK fetch failure |
| `eap_teapv2.c` | `eap_teapv2_get_cmk()` | 1295 | eap_teapv2_derive_imck() failure |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1332 | eap_teapv2_validate_crypto_binding() failure |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1332 | eap_teapv2_get_cmk() failure |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1357 | MSK Compound MAC mismatch |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1379 | EMSK Compound MAC mismatch |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1387 | Server sent only EMSK MAC but no local EMSK was available |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1406 | Neither MSK nor EMSK path selected |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1417 | eap_teapv2_derive_msk() failure |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1427 | eap_teapv2_session_id() failure |
| `eap_teapv2.c` | `eap_teapv2_process_crypto_binding()` | 1435 | eap_teapv2_write_crypto_binding() failure |

## `eap_teapv2.c` — Phase 2 Method Handling

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_phase2_request()` | 916 | Request too short |
| `eap_teapv2.c` | `eap_teapv2_phase2_request()` | 925 | Expanded-header request too short |
| `eap_teapv2.c` | `eap_teapv2_phase2_request()` | 958 | Phase 2 method initialization failure |
| `eap_teapv2.c` | `eap_teapv2_phase2_request()` | 993 | Inner method returned no response and final decision is FAIL |
| `eap_teapv2.c` | `eap_teapv2_process_eap_payload_tlv()` | 1041 | EAP Payload TLV too short |
| `eap_teapv2.c` | `eap_teapv2_process_eap_payload_tlv()` | 1049 | EAP length field exceeds TLV buffer |
| `eap_teapv2.c` | `eap_teapv2_process_eap_payload_tlv()` | 1055 | EAP code is not Request |
| `eap_teapv2.c` | `eap_teapv2_process_eap_payload_tlv()` | 1062 | Phase 2 request processing failure |
| `eap_teapv2.c` | `eap_teapv2_process_basic_auth_req()` | 1092 | No username or password configured, or value exceeds 255 bytes (NAK sent — not fatal) |

## `eap_teapv2.c` — CSR / PKCS#10 / PKCS#7

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_apply_csr_attrs()` | 362 | Invalid CSR Attributes DER encoding |
| `eap_teapv2.c` | `eap_teapv2_apply_csr_attrs()` | 372 | ASN.1 parse error |
| `eap_teapv2.c` | `eap_teapv2_apply_csr_attrs()` | 414 | Missing SET OF values in attribute |
| `eap_teapv2.c` | `eap_teapv2_apply_csr_attrs()` | 477 | crypto_csr_set_name() failure |
| `eap_teapv2.c` | `eap_teapv2_apply_csr_attrs()` | 495 | crypto_csr_set_attribute() failure |
| `eap_teapv2.c` | `eap_teapv2_populate_csr_subject()` | 289 | Cannot extract subject from existing cert and no identity available |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 522 | No certificate configuration available |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 529 | EC key generation failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 533 | Private key export failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 537 | CSR init or set_ec_public_key failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 546 | CSR Attribute application failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 551 | CSR subject population failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 560 | crypto_csr_sign() failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 611 | Private key blob storage failure |
| `eap_teapv2.c` | `eap_teapv2_build_pkcs10_tlv()` | 619 | Output TLV allocation failure |
| `eap_teapv2.c` | `eap_teapv2_process_pkcs7()` | 656 | PKCS#7 bundle parse failure |
| `eap_teapv2.c` | `eap_teapv2_process_pkcs7()` | 662 | Unsolicited PKCS#7 received (no prior PKCS#10 request) |
| `eap_teapv2.c` | `eap_teapv2_process_pkcs7()` | 671 | Certificate blob storage failure |
| `eap_teapv2.c` | `eap_teapv2_process_trusted_server_root()` | 156 | No certificate configuration available |
| `eap_teapv2.c` | `eap_teapv2_process_trusted_server_root()` | 165 | eap_teapv2_store_blob() failure |

## `eap_teapv2.c` — Decrypted TLV Processing

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_parse_decrypted()` | 1463 | TLV length overflows remaining buffer |
| `eap_teapv2.c` | `eap_teapv2_derive_msk()` | 791 | eap_teapv2_derive_eap_msk() failure |
| `eap_teapv2.c` | `eap_teapv2_derive_msk()` | 791 | eap_teapv2_derive_eap_emsk() failure |
| `eap_teapv2.c` | `eap_teapv2_session_id()` | 1295 | Memory allocation failure |
| `eap_teapv2.c` | `eap_teapv2_session_id()` | 1303 | tls_get_tls_unique() failure or buffer overflow |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1530 | TLV parsing failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1542 | Server sent Result=Failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1554 | Intermediate-Result=Success with no Crypto-Binding (when cb_required) |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1564 | Result=Success with no Crypto-Binding (when cb_required and iresult not yet verified) |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1574 | Inner method completed with no Intermediate-Result TLV |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1619 | Crypto-Binding TLV received without accompanying Result or Intermediate-Result=Success |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1545 | Crypto-Binding processing failure (TEAPV2_ERROR_TUNNEL_COMPROMISE_ERROR) |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1631 | Phase 2 EAP type update failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1643 | CSR Attributes buffer allocation failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1649 | PKCS#10 TLV build failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1661 | PKCS#7 processing failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1670 | Key derivation failure after PKCS#7 |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1686 | Inner EAP response processing failure |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1747 | Key derivation failure after basic auth |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1764 | Key derivation failure at final completion |
| `eap_teapv2.c` | `eap_teapv2_process_decrypted()` | 1786 | Phase 2 encryption failure |
| `eap_teapv2.c` | `eap_teapv2_decrypt()` | 1843 | Decrypted Phase 2 TLV frame too short (< 4 bytes) |
| `eap_teapv2.c` | `eap_teapv2_decrypt()` | 1834 | eap_peer_tls_decrypt() failure |

## `eap_teapv2.c` — Main `process()` Entry Point

| File | Function | Line | Error Condition |
|---|---|---|---|
| `eap_teapv2.c` | `eap_teapv2_process()` | 2058 | TLS peer process init failure |
| `eap_teapv2.c` | `eap_teapv2_process()` | 2065 | Start message processing failure |
| `eap_teapv2.c` | `eap_teapv2_process()` | 2076 | Outer TLVs present in non-Start message |
| `eap_teapv2.c` | `eap_teapv2_process()` | 2118 | External certificate check explicitly failed |
| `eap_teapv2.c` | `eap_teapv2_process()` | 2132 | TLS handshake helper failure |
| `eap_teapv2.c` | `eap_teapv2_process()` | 2163 | Key derivation failure after TLS handshake established |
| `eap_teapv2.c` | `eap_teapv2_process()` | 2087 | Phase 2 decryption failure |
