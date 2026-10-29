/* ABI 1. Inputs are borrowed for each call. All non-null pointers must be
 * aligned, initialized and valid for their lengths. Text is UTF-8 without a
 * terminating NUL. Null/zero denotes absent optional text; non-null/zero is
 * present empty text. Results own all their views until result_free.
 * Handles are library-specific. Mutation/free require exclusive access.
 * Operations are never automatically replayed after uncertain I/O errors.
 * timeout_ms is positive and covers connect, send and receive together.
 * Result errors are POSIX codes, and result_failure gives their kind,
 * PEIOS_TRUST_FAILURE_*; both are stable. Diagnostic wording is not. */
#ifndef PEIOS_TRUST_H
#define PEIOS_TRUST_H
#include "trust-types.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct peios_trust_result peios_trust_result;
uint32_t peios_trust_abi_version(void);
void peios_trust_result_free(peios_trust_result *result);
int32_t peios_trust_result_error(const peios_trust_result *result);
/* The kind of failure: NONE on success, OTHER for a null result. */
uint32_t peios_trust_result_failure(const peios_trust_result *result);
peios_trust_bytes peios_trust_result_message(const peios_trust_result *result);
const peios_trust_bytes *peios_trust_result_text(const peios_trust_result *result);
const peios_trust_bytes *peios_trust_result_bytes(const peios_trust_result *result);
const uint32_t *peios_trust_result_boolean(const peios_trust_result *result);
const peios_trust_status *peios_trust_result_status(const peios_trust_result *result);
const peios_trust_parsed *peios_trust_result_parsed(const peios_trust_result *result);
const peios_trust_details *peios_trust_result_details(const peios_trust_result *result);
const peios_trust_root_list *peios_trust_result_root_list(const peios_trust_result *result);
const peios_trust_distrusted_list *
peios_trust_result_distrusted_list(const peios_trust_result *result);
/* A list of byte strings: each span is one certificate's DER. */
const peios_trust_strings *peios_trust_result_byte_list(const peios_trust_result *result);
/* Read the daemon status. */
peios_trust_result *peios_trust_get_status(peios_trust_bytes path, uint64_t timeout_ms);
/* Read a complete, generation-consistent trust snapshot. */
peios_trust_result *peios_trust_roots(peios_trust_bytes path, uint64_t timeout_ms,
                                      uint32_t with_der, peios_trust_bytes purpose);
/* Request trust-store recomposition using the caller's rights. */
peios_trust_result *peios_trust_reload(peios_trust_bytes path, uint64_t timeout_ms);
/* Decode exactly one PEM or DER certificate. */
peios_trust_result *peios_trust_certificate(peios_trust_bytes bytes, peios_trust_bytes description);
/* Inspect certificate fields without trusting the certificate. */
peios_trust_result *peios_trust_inspect(peios_trust_bytes der);
/* Validate a candidate root using the existing certificate policy. */
peios_trust_result *peios_trust_vet(peios_trust_bytes der);
/* Check whether a certificate-store name is usable. */
peios_trust_result *peios_trust_usable_name(peios_trust_bytes name);
/* Check the caller's reload access. */
peios_trust_result *peios_trust_may_reload(void);
/* Check the caller's registry write access. */
peios_trust_result *peios_trust_may_change(void);
/* Check compatibility-output configuration access. */
peios_trust_result *peios_trust_may_set_compat(void);
/* Set compatibility output mode as the caller. */
peios_trust_result *peios_trust_set_compat(uint32_t mode);
/* Add a certificate under the caller's registry permissions. */
peios_trust_result *peios_trust_add(peios_trust_bytes name, peios_trust_bytes der,
                                    peios_trust_strings purposes);
/* Remove an added certificate as the caller. */
peios_trust_result *peios_trust_remove(peios_trust_bytes name);
/* Read durable distrust entries. */
peios_trust_result *peios_trust_get_distrusted(void);
/* Distrust a fingerprint as the caller; return the subject of a matching effective certificate. */
peios_trust_result *peios_trust_distrust(peios_trust_bytes fingerprint, peios_trust_bytes reason);
/* Remove a distrust entry as the caller. */
peios_trust_result *peios_trust_restore(peios_trust_bytes fingerprint);
/* Subscriptions are exclusively owned. Timeout preserves partial input.
 * Other transport/protocol errors close the stream. Free each handle once. */
typedef struct peios_trust_subscription peios_trust_subscription;
peios_trust_result *peios_trust_subscribe(peios_trust_bytes path, uint64_t timeout_ms,
                                          uint32_t with_der, peios_trust_subscription **out);
peios_trust_result *peios_trust_subscription_next(peios_trust_subscription *subscription,
                                                  uint64_t timeout_ms);
void peios_trust_subscription_free(peios_trust_subscription *subscription);
uint64_t peios_trust_result_generation(const peios_trust_result *result);
peios_trust_result *peios_trust_resolve(peios_trust_bytes argument);
/* Return a certificate's SHA-256 fingerprint, lowercase hex, as text. */
peios_trust_result *peios_trust_fingerprint(peios_trust_bytes der);
/* Return a certificate's DER as one PEM block of 64 columns, as text. */
peios_trust_result *peios_trust_to_pem(peios_trust_bytes der);
/* Return the DER of every CERTIFICATE block of a PEM document, as a byte list. */
peios_trust_result *peios_trust_from_pem(peios_trust_bytes text);
/* Return a fingerprint as compared: lowercase, separators removed, as text. */
peios_trust_result *peios_trust_normalise_fingerprint(peios_trust_bytes text);
/* Resolve a whole fingerprint, or an unambiguous prefix of at least eight
 * digits of one of fingerprints, without contacting trustd. No match fails
 * with PEIOS_TRUST_FAILURE_NOT_FOUND. */
peios_trust_result *peios_trust_fingerprint_in(peios_trust_bytes text,
                                               peios_trust_strings fingerprints);
/* Return the self-relative descriptor trustd checks against when the
 * ControlSecurity value is absent, as bytes. */
peios_trust_result *peios_trust_default_control_security(void);
#ifdef __cplusplus
}
#endif
#endif
