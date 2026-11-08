#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t pvia_god_output_provider_abi_version(void);
int32_t pvia_god_output_provider_capabilities(
    uint64_t* out_words, size_t* inout_word_count);
int32_t pvia_god_output_provider_prove(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* witness_words, size_t witness_word_count,
    uint64_t* proof_words, size_t* inout_proof_word_count);
int32_t pvia_god_output_provider_verify(
    const uint64_t* statement_words, size_t statement_word_count,
    const uint64_t* proof_words, size_t proof_word_count);
size_t pvia_god_output_provider_last_error(
    uint8_t* out_bytes, size_t* inout_capacity);

#ifdef __cplusplus
}
#endif

#define PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION 1U
#define PVIA_GOD_OUTPUT_PROVIDER_CAPABILITY_ABI_DOMAIN 0x5056474f44434142ULL
#define PVIA_GOD_OUTPUT_PROVIDER_CAPABILITY_ABI_WORDS 26U
#define PVIA_GOD_OUTPUT_PROVIDER_ABI_VERSION_SYMBOL "pvia_god_output_provider_abi_version"
#define PVIA_GOD_OUTPUT_PROVIDER_ABI_CAPABILITIES_SYMBOL "pvia_god_output_provider_capabilities"
#define PVIA_GOD_OUTPUT_PROVIDER_ABI_PROVE_SYMBOL "pvia_god_output_provider_prove"
#define PVIA_GOD_OUTPUT_PROVIDER_ABI_VERIFY_SYMBOL "pvia_god_output_provider_verify"
#define PVIA_GOD_OUTPUT_PROVIDER_ABI_LAST_ERROR_SYMBOL "pvia_god_output_provider_last_error"
