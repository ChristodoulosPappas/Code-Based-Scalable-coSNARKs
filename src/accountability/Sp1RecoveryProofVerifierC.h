#ifndef PVIA_SP1_RECOVERY_VERIFIER_C_H
#define PVIA_SP1_RECOVERY_VERIFIER_C_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* 1=verified, 0=rejected, -1=invalid arguments. */
int32_t pvia_sp1_recovery_verify_artifact(
    const uint8_t* artifact_bytes, size_t artifact_length,
    const uint64_t* expected_statement_words, size_t expected_statement_word_count);
#ifdef __cplusplus
}
#endif
#endif
