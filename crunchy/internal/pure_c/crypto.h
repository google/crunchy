/*
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Contains the vtable and struct for ccr_crypter. Used by implementations of
 * ccr_crypter. */
#ifndef CRUNCHY_INTERNAL_PURE_C_CRYPTO_H_
#define CRUNCHY_INTERNAL_PURE_C_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

#include "crunchy/internal/pure_c/crypto_interfaces.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ccr_crypter_vtable {
  int (*encrypt)(const ccr_crypter* self, const uint8_t* plaintext,
                 size_t plaintext_length, const uint8_t* associated_data,
                 size_t associated_data_length, uint8_t* ciphertext,
                 size_t ciphertext_length, size_t* bytes_written,
                 ccr_error* error);
  size_t (*max_ciphertext_length)(const ccr_crypter* self,
                                  size_t plaintext_length);
  int (*decrypt)(const ccr_crypter* self, const uint8_t* ciphertext,
                 size_t ciphertext_length, const uint8_t* associated_data,
                 size_t associated_data_length, uint8_t* plaintext,
                 size_t plaintext_length, size_t* bytes_written,
                 ccr_error* error);
  size_t (*max_plaintext_length)(const ccr_crypter* self,
                                 size_t ciphertext_length);
  void (*free)(ccr_crypter* self);
} ccr_crypter_vtable;

struct ccr_crypter {
  const ccr_crypter_vtable* vtable;
};

typedef struct ccr_macer_vtable {
  int (*sign)(const ccr_macer* self, const uint8_t* message,
              size_t message_length, uint8_t* signature,
              size_t signature_length, size_t* bytes_written, ccr_error* error);
  size_t (*max_signature_length)(const ccr_macer* self);
  int (*verify)(const ccr_macer* self, const uint8_t* message,
                size_t message_length, const uint8_t* signature,
                size_t signature_length, ccr_error* error);
  void (*free)(ccr_macer* self);
} ccr_macer_vtable;

struct ccr_macer {
  const ccr_macer_vtable* vtable;
};

typedef struct ccr_signer_vtable {
  int (*sign)(const ccr_signer* self, const uint8_t* message,
              size_t message_length, uint8_t* signature,
              size_t signature_length, size_t* bytes_written, ccr_error* error);
  size_t (*max_signature_length)(const ccr_signer* self);
  void (*free)(ccr_signer* self);
} ccr_signer_vtable;

struct ccr_signer {
  const ccr_signer_vtable* vtable;
};

typedef struct ccr_verifier_vtable {
  int (*verify)(const ccr_verifier* self, const uint8_t* message,
                size_t message_length, const uint8_t* signature,
                size_t signature_length, ccr_error* error);
  void (*free)(ccr_verifier* self);
} ccr_verifier_vtable;

struct ccr_verifier {
  const ccr_verifier_vtable* vtable;
};

typedef struct ccr_hybrid_encrypter_vtable {
  int (*encrypt)(const ccr_hybrid_encrypter* self, const uint8_t* plaintext,
                 size_t plaintext_length, uint8_t* ciphertext,
                 size_t ciphertext_length, size_t* bytes_written,
                 ccr_error* error);
  size_t (*max_ciphertext_length)(const ccr_hybrid_encrypter* self,
                                  size_t plaintext_length);
  void (*free)(ccr_hybrid_encrypter* self);
} ccr_hybrid_encrypter_vtable;

struct ccr_hybrid_encrypter {
  const ccr_hybrid_encrypter_vtable* vtable;
};

typedef struct ccr_hybrid_decrypter_vtable {
  int (*decrypt)(const ccr_hybrid_decrypter* self, const uint8_t* ciphertext,
                 size_t ciphertext_length, uint8_t* plaintext,
                 size_t plaintext_length, size_t* bytes_written,
                 ccr_error* error);
  size_t (*max_plaintext_length)(const ccr_hybrid_decrypter* self,
                                 size_t ciphertext_length);
  void (*free)(ccr_hybrid_decrypter* self);
} ccr_hybrid_decrypter_vtable;

struct ccr_hybrid_decrypter {
  const ccr_hybrid_decrypter_vtable* vtable;
};

#ifdef __cplusplus
}
#endif

#endif  /* CRUNCHY_INTERNAL_PURE_C_CRYPTO_H_ */
