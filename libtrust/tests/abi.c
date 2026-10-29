#include <assert.h>
#include <errno.h>
#include <peios/trust.h>
int main(void) {
    assert(peios_trust_abi_version() == 1);
    peios_trust_bytes absent = {0};
    peios_trust_result *result = peios_trust_get_status(absent, 10);
    assert(result != 0);
    assert(peios_trust_result_error(result) == EINVAL);
    assert(peios_trust_result_message(result).len != 0);
    assert(peios_trust_result_status(result) == 0);
    assert(peios_trust_result_failure(result) == PEIOS_TRUST_FAILURE_OTHER);
    peios_trust_result_free(result);
    peios_trust_result_free(0);
    assert(peios_trust_result_failure(0) == PEIOS_TRUST_FAILURE_OTHER);

    /* Certificate helpers need no daemon. */
    result = peios_trust_fingerprint(absent);
    assert(peios_trust_result_error(result) == 0);
    assert(peios_trust_result_failure(result) == PEIOS_TRUST_FAILURE_NONE);
    assert(peios_trust_result_text(result)->len == 64);
    peios_trust_result_free(result);
    result = peios_trust_vet(absent);
    assert(peios_trust_result_error(result) == EINVAL);
    assert(peios_trust_result_failure(result) == PEIOS_TRUST_FAILURE_MALFORMED);
    peios_trust_result_free(result);
    result = peios_trust_from_pem(absent);
    assert(peios_trust_result_byte_list(result)->len == 0);
    peios_trust_result_free(result);
    peios_trust_bytes prefix = {(const uint8_t *)"deadbeef", 8};
    peios_trust_strings none = {0};
    result = peios_trust_fingerprint_in(prefix, none);
    assert(peios_trust_result_error(result) == ENOENT);
    assert(peios_trust_result_failure(result) == PEIOS_TRUST_FAILURE_NOT_FOUND);
    peios_trust_result_free(result);
    result = peios_trust_default_control_security();
    assert(peios_trust_result_bytes(result)->len > 0);
    peios_trust_result_free(result);
    return 0;
}
