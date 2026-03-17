## Overview of EAP-PPT

The draft defines EAP-PPT (EAP using Privacy Pass Token, type 57 / 0x39) as a **unilateral, anonymous inner EAP method** that must always run inside a server-authenticated TLS tunnel (TEAP, PEAP, EAP-TTLS, EAP-FAST). The peer authenticates by presenting a Privacy Pass token (RFC 9577/9578); the server redeems the token to grant access. All message payloads are JSON. There is no mutual authentication.

---

## 1. New Source Files Required

### `src/eap_peer/eap_ppt.c` — peer (wpa_supplicant side)

This implements the peer state machine. The core lifecycle:

```
INIT → CHALLENGE_SENT → [CHANNEL_BINDING_SENT] → DONE
```

Required functions matching `struct eap_method`:

| Function | Responsibility |
|---|---|
| `eap_ppt_init()` | Allocate state; load token(s) from config |
| `eap_ppt_deinit()` | Free state, zeroize token material |
| `eap_ppt_process()` | Dispatch on Subtype, build response |
| `eap_ppt_isKeyAvailable()` | True after EAP-Success received |
| `eap_ppt_getKey()` | Return 64-byte MSK |
| `eap_ppt_get_emsk()` | Return 64-byte EMSK |
| `eap_peer_ppt_register()` | Register the method |

The `process()` function must handle three incoming subtypes:
- **Subtype 1 (Challenge):** Parse the JSON `challenges` array, find a held token matching one challenge (by `token_type` and `issuer_name` inside the TokenChallenge), base64url-decode the token, build `EAP-Response/PPT-Challenge` JSON. If no token is found, respond with an empty token string.
- **Subtype 2 (Error):** Parse the JSON error code and description, log it, send `EAP-Response/PPT-Error` (no data), set state to DONE/FAIL.
- **Subtype 3 (Channel-Binding):** Build the channel-binding response per RFC 6677 §5.3.

### `src/eap_server/eap_server_ppt.c` — server (hostapd side)

This implements the authenticator-side state machine:

```
INIT → [CHALLENGE_SENT → CHALLENGE_RECEIVED] → 
       [ERROR_SENT → ERROR_RECEIVED] →
       [CHANNEL_BINDING_SENT → CHANNEL_BINDING_RECEIVED] → DONE
```

Required functions matching `struct eap_method` (server variant):

| Function | Responsibility |
|---|---|
| `eap_ppt_init()` | Allocate state; prepare challenge from config |
| `eap_ppt_reset()` | Free state |
| `eap_ppt_buildReq()` | Construct EAP-Request for current state |
| `eap_ppt_check()` | Validate that response subtype matches request subtype |
| `eap_ppt_process()` | Parse response; drive state machine |
| `eap_ppt_isDone()` | Return true when in terminal state |
| `eap_ppt_isSuccess()` | Return true if SUCCESS state |
| `eap_ppt_getKey()` | Return MSK |
| `eap_ppt_get_emsk()` | Return EMSK |
| `eap_server_ppt_register()` | Register the method |

The `buildReq()` function generates JSON for each state:
- Subtype 1: JSON `challenges` array (one or more `TokenChallenge` structures per RFC 9577 §2.2.1, base64url-encoded with optional `extension-types`)
- Subtype 2: JSON error with `code`, optional `description`, optional `session-timeout`
- Subtype 3: empty body (Channel-Binding request)

The `process()` function for Subtype 1 (challenge response):
- Base64url-decode received token
- Verify token structure (token type, issuer name, nonce, challenge digest per RFC 9577)
- Call token redemption (see §5 below)
- On failure, transition to ERROR state; on success, optionally transition to CHANNEL_BINDING state or DONE/SUCCESS

---

## 2. Changes to Existing Files

### eap_defs.h
Add the new EAP type:
```c
EAP_TYPE_PPT = 57 /* draft-ietf-emu-eap-ppt */,
```
(Type 57 is the value claimed in the draft: `0x39`. This must eventually be confirmed/assigned by IANA.)

### eap_methods.h
Add the peer registration prototype:
```c
int eap_peer_ppt_register(void);
```

### eap_methods.h
Add the server registration prototype:
```c
int eap_server_ppt_register(void);
```

### eap_register.c
Add peer registration:
```c
#ifdef EAP_PPT
    if (ret == 0)
        ret = eap_peer_ppt_register();
#endif /* EAP_PPT */
```

### eap_register.c
Add server registration:
```c
#ifdef EAP_SERVER_PPT
    if (ret == 0)
        ret = eap_server_ppt_register();
#endif /* EAP_SERVER_PPT */
```

### Makefile
```makefile
ifdef CONFIG_EAP_PPT
CFLAGS += -DEAP_PPT
OBJS += ../src/eap_peer/eap_ppt.o
endif
```

### Makefile
```makefile
ifdef CONFIG_EAP_SERVER_PPT
CFLAGS += -DEAP_SERVER_PPT
OBJS += ../src/eap_server/eap_server_ppt.o
endif
```

---

## 3. Configuration Extensions

### wpa_supplicant (eap_config.h)
When EAP-PPT is used as an inner method (e.g. inside TEAP), the outer network block specifies `inner_eap=PPT`. The peer needs new fields:

```c
/* Path to a file or directory containing stored Privacy Pass tokens */
char *ppt_token_store;

/* Single base64url-encoded Privacy Pass token (alternative to file) */
char *ppt_token;
```

### hostapd (hostapd.conf)
The server needs:
- `eap_ppt_issuer_key` — the Issuer public key (base64url), used to verify token signatures
- `eap_ppt_issuer_name` — the expected Issuer hostname in the TokenChallenge
- `eap_ppt_origin_name` — the Origin name encoded in the TokenChallenge
- `eap_ppt_token_type` — `1` (VOPRF/public-verifiable) or `2` (RSA Blind Sig)
- `eap_ppt_redemption_url` — optional URL of an external token redemption/verification service

---

## 4. JSON Handling

The hostap codebase has no JSON library. The implementation needs one of:

1. **Bundle a minimal JSON library** such as [cJSON](https://github.com/DaveGamble/cJSON) (single `.c`/`.h` file, BSD-licensed) placed under `src/utils/cjson.c`
2. **Hand-written parser** for the narrow, well-defined schema (predictable keys, no nesting beyond one array level) — viable given the simplicity of the spec's JSON

The JSON schema is simple enough that a custom parser is practical. The challenge message has a fixed structure with `challenges[]` containing `challenge`, `token-key`, and optional `extension-types`. The response has just `token` and optional `extensions`.

---

## 5. Privacy Pass Token Verification (Crypto)

This is the most substantial new cryptographic component. RFC 9578 defines two issuance protocols:

- **Type 1 (0x0001):** VOPRF-based (Verifiable Oblivious PRF) — server holds Issuer public key and runs a verification step using HPKE/VOPRF primitives (RFC 9497)
- **Type 2 (0x0002):** RSA Blind Signature (RSABSSA per RFC 9474) — server verifies a blind RSA signature against the Issuer's public key

Neither is in the existing hostap crypto library. Options:

- Use OpenSSL/libcrypto for RSA blind signature verification (Type 2) — OpenSSL 3.2+ has RSABSSA support
- For Type 1: requires a VOPRF library (e.g., `libboringssl` or a standalone VOPRF implementation)
- Alternatively, proxy redemption to an external service via HTTP (as the draft allows) — the server POSTs the token to a Token Redemption Server

The simplest path to a working implementation is **external HTTP redemption**: the hostapd EAP-PPT server calls out to a configured redemption endpoint (an HTTP POST of the token), and uses the response to determine success/failure. The `src/utils/http_utils.c` or `libcurl` would be needed for this.

---

## 6. Key Material Derivation

Section 6.6 specifies:
```
Context = Type || token
Key_Material = TLS_Exporter("EXPORTER_EAP_PPT_Key_Material", Context, 128)
MSK  = Key_Material[0..63]
EMSK = Key_Material[64..127]
```

The TLS exporter must be called on the **outer tunnel's** TLS session. This is available on both the peer and server sides through the tunnel EAP method's `tls_conn` handle (see `eap_tls_common.h` and its `eap_tls_key_derivation()` wrappers). This is the same mechanism used by TEAP (eap_server_teap.c) for its `session_key_seed`. The concrete call would look like:

```c
tls_connection_export_key(sm->ssl_ctx, data->ssl.conn,
    "EXPORTER_EAP_PPT_Key_Material",
    context, context_len,       /* Type byte || raw token bytes */
    key_material, 128);
```

Access to `sm->ssl_ctx` and the tunnel `ssl.conn` from within the inner method requires either passing the outer TLS state as a parameter or adding a callback in the peer `eap_sm` and server `eap_sm` structures — similar to what PEAP does when calling `eap_tls_derived_key()`.

---

## 7. Channel Binding

The Channel-Binding exchange (Subtype 3) must follow RFC 6677 §5.3. The implementation is straightforward — the peer collects NAS-Identifier, NAS-IP-Address, Called-Station-Id, etc. (already parsed in wpa_supplicant via RADIUS attributes) and formats them per the spec. The server validates them against what it knows from the RADIUS Access-Request. This is similar to what TEAP already does with its Channel-Binding TLV (see eap_server_teap.c).

---

## 8. Token Storage on the Peer

wpa_supplicant has no built-in Privacy Pass token store. A new module `src/eap_peer/eap_ppt_tokens.c` would be needed implementing:
- Load tokens from a JSON or binary file at startup
- Match a token to a challenge (compare `token_type`, `issuer_name`, `origin_name` fields in the TokenChallenge, and optionally required `extension-types`)
- Mark a token as used after successful redemption (to prevent local double-spend)
- Rotate/expire tokens

The configuration could follow the pattern of EAP-FAST PAC files (`eap_fast_pac.c`).

---

## 9. Security Considerations for the Implementation

- The token is cryptographic secret material; it must be handled like a password: `os_memset()`-cleared on free, never logged in plaintext
- Empty-token responses (no matching token found) must still go through the full EAP exchange (no short-circuit) to avoid leaking timing information
- The Subtype byte must be validated before any JSON parsing to prevent crafted packets from triggering JSON parser bugs
- Double-spend detection on the server side requires persistent state (a redeemed-token set, keyed by nonce); this state must survive restarts if the redemption window spans restarts

---

## 10. Summary of Work Items (Rough Priority Order)

| # | Item | Complexity |
|---|---|---|
| 1 | Add `EAP_TYPE_PPT = 57` to eap_defs.h | Trivial |
| 2 | Add `eap_peer_ppt_register` / `eap_server_ppt_register` prototypes and call-sites | Trivial |
| 3 | Add build system hooks in both Makefiles | Trivial |
| 4 | Add a minimal JSON generator (for server) and parser (for both) | Small |
| 5 | Write `src/eap_peer/eap_ppt.c` — peer state machine, token lookup, key derivation | Medium |
| 6 | Write `src/eap_server/eap_server_ppt.c` — server state machine, challenge construction | Medium |
| 7 | Token storage module for wpa_supplicant peer | Medium |
| 8 | Token verification/redemption — either external HTTP call or built-in crypto | Large |
| 9 | TLS exporter access from inner method context | Medium |
| 10 | Privacy Pass VOPRF / RSA-blind-sig crypto primitives (if not using HTTP relay) | Large |
| 11 | Add peer config fields and wpa_supplicant config parsing | Small |
| 12 | Add hostapd config fields for issuer key, origin name, etc. | Small |
| 13 | Channel-binding subtype (Subtype 3) | Small |
| 14 | RADIUS session-timeout passthrough for conditional access (error code 8) | Small |

The biggest implementation risks are (a) the JSON library choice, (b) the Privacy Pass token verification crypto (which requires either OpenSSL 3.x RSA-blind-sig support for Type 2 tokens or a new VOPRF library for Type 1), and (c) thread-safe access to the outer TLS session handle for key derivation from within the inner EAP method. Using an HTTP-based external redemption service for (b) as a first step would unlock an initial working implementation with manageable scope, deferring the built-in cryptographic verifier to a follow-on phase.
