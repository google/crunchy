// Copyright 2017 The CrunchyCrypt Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef CRUNCHY_INTERNAL_BINDINGS_CRYPTO_H_
#define CRUNCHY_INTERNAL_BINDINGS_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

#include "crunchy/internal/pure_c/crypto_interfaces.h"

#ifdef __cplusplus
extern "C" {
#endif

ccr_crypter* ccr_crypter_new_from_serialized_keyset(const uint8_t* keyset_bytes,
                                                    size_t keyset_length,
                                                    ccr_error* error);

ccr_macer* ccr_macer_new_from_serialized_keyset(const uint8_t* keyset_bytes,
                                                size_t keyset_length,
                                                ccr_error* error);

ccr_signer* ccr_signer_new_from_serialized_keyset(const uint8_t* keyset_bytes,
                                                  size_t keyset_length,
                                                  ccr_error* error);

ccr_verifier* ccr_verifier_new_from_serialized_keyset(
    const uint8_t* keyset_bytes, size_t keyset_length, ccr_error* error);

ccr_hybrid_encrypter* ccr_hybrid_encrypter_new_from_serialized_keyset(
    const uint8_t* keyset_bytes, size_t keyset_length, ccr_error* error);

ccr_hybrid_decrypter* ccr_hybrid_decrypter_new_from_serialized_keyset(
    const uint8_t* keyset_bytes, size_t keyset_length, ccr_error* error);

#ifdef __cplusplus
}
#endif

#endif  // CRUNCHY_INTERNAL_BINDINGS_CRYPTO_H_
