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

#ifndef CRUNCHY_INTERNAL_PURE_C_CRYPTO_INTERFACES_H_
#define CRUNCHY_INTERNAL_PURE_C_CRYPTO_INTERFACES_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Allocates memory. Guaranteed to return a non-NULL value. Target must be freed
 * with a call to ccr_free.
 */
void* ccr_malloc(size_t length);

/* Frees memory allocated with ccr_malloc. */
void ccr_free(void* ptr);

/* An error, struct. ccr_error_init must be called after creation and
 * ccr_error_cleanup must be called before destruction. */
typedef struct ccr_error { char* message; } ccr_error;

/* Initializes an error struct */
void ccr_error_init(ccr_error* error);

/* Frees the members of the struct, but does not free the struct itself. */
void ccr_error_cleanup(ccr_error* self);

typedef struct ccr_crypter ccr_crypter;

/**
 * Encrypts the plaintext, putting the result in the ciphertext buffer.
 * *bytes_written will be set to the amount of ciphertext buffer used. The
 * ciphertext buffer should have at least as many bytes as is returned by
 * ccr_crypter_max_ciphertext_length.
 */
int ccr_crypter_encrypt(const ccr_crypter* self, const uint8_t* plaintext,
                        size_t plaintext_length, const uint8_t* associated_data,
                        size_t associated_data_length, uint8_t* ciphertext,
                        size_t ciphertext_length, size_t* bytes_written,
                        ccr_error* error);

/**
 * Returns the size of the ciphertext buffer needed for the
 * ccr_crypter_encrypt function.
 */
size_t ccr_crypter_max_ciphertext_length(const ccr_crypter* self,
                                         size_t plaintext_length);

/**
 * Decrypts the ciphertext, putting the result in the plaintext buffer.
 * *bytes_written will be set to the amount of plaintext buffer used. The
 * plaintext buffer should have at least as many bytes as is returned by
 * ccr_crypter_max_plaintext_length.
 */
int ccr_crypter_decrypt(const ccr_crypter* self, const uint8_t* ciphertext,
                        size_t ciphertext_length,
                        const uint8_t* associated_data,
                        size_t associated_data_length, uint8_t* plaintext,
                        size_t plaintext_length, size_t* bytes_written,
                        ccr_error* error);

/**
 * Returns the size of the plaintext buffer needed for the
 * ccr_crypter_decrypt function.
 */
size_t ccr_crypter_max_plaintext_length(const ccr_crypter* self,
                                        size_t ciphertext_length);

/**
 * Destructs the ccr_crypter and frees the allocated memory.
 */
void ccr_crypter_free(ccr_crypter* self);

typedef struct ccr_macer ccr_macer;

/**
 * Macs the message, putting the result into the signature buffer.
 */
int ccr_macer_sign(const ccr_macer* self, const uint8_t* message,
                   size_t message_length, uint8_t* signature,
                   size_t signature_length, size_t* bytes_written,
                   ccr_error* error);

/**
 * Returns the size of the signature buffer needed for the ccr_macer_sign
 * function.
 */
size_t ccr_macer_max_signature_length(const ccr_macer* self);

/**
 * Verifies that the signature matches the message.
 */
int ccr_macer_verify(const ccr_macer* self, const uint8_t* message,
                     size_t message_length, const uint8_t* signature,
                     size_t signature_length, ccr_error* error);

/**
 * Destructs the ccr_macer and frees the allocated memory.
 */
void ccr_macer_free(ccr_macer* self);

typedef struct ccr_signer ccr_signer;

/**
 * Signs the message, putting the result into the signature buffer.
 */
int ccr_signer_sign(const ccr_signer* self, const uint8_t* message,
                    size_t message_length, uint8_t* signature,
                    size_t signature_length, size_t* bytes_written,
                    ccr_error* error);

/**
 * Returns the size of the signature buffer needed for the ccr_signer_sign
 * function.
 */
size_t ccr_signer_max_signature_length(const ccr_signer* self);

/**
 * Destructs the ccr_signer and frees the allocated memory.
 */
void ccr_signer_free(ccr_signer* self);

typedef struct ccr_verifier ccr_verifier;

/**
 * Verifies that the signatures matches the message.
 */
int ccr_verifier_verify(const ccr_verifier* self, const uint8_t* message,
                        size_t message_length, const uint8_t* signature,
                        size_t signature_length, ccr_error* error);

/**
 * Destructs the ccr_crypter and frees the allocated memory.
 */
void ccr_verifier_free(ccr_verifier* self);

typedef struct ccr_hybrid_encrypter ccr_hybrid_encrypter;

/**
 * Encrypts the plaintext, putting the result in the ciphertext buffer.
 * *bytes_written will be set to the amount of ciphertext buffer used. The
 * ciphertext buffer should have at least as many bytes as is returned by
 * ccr_hybrid_encrypter_max_ciphertext_length.
 */
int ccr_hybrid_encrypter_encrypt(const ccr_hybrid_encrypter* self,
                                 const uint8_t* plaintext,
                                 size_t plaintext_length, uint8_t* ciphertext,
                                 size_t ciphertext_length,
                                 size_t* bytes_written, ccr_error* error);

/**
 * Returns the size of the ciphertext buffer needed for the
 * ccr_hybrid_encrypter_encrypt function.
 */
size_t ccr_hybrid_encrypter_max_ciphertext_length(
    const ccr_hybrid_encrypter* self, size_t plaintext_length);

/**
 * Destructs the ccr_hybrid_encrypter and frees the allocated memory.
 */
void ccr_hybrid_encrypter_free(ccr_hybrid_encrypter* self);

typedef struct ccr_hybrid_decrypter ccr_hybrid_decrypter;

/**
 * Decrypts the ciphertext, putting the result in the plaintext buffer.
 * *bytes_written will be set to the amount of plaintext buffer used. The
 * plaintext buffer should have at least as many bytes as is returned by
 * ccr_hybrid_decrypter_max_plaintext_length.
 */
int ccr_hybrid_decrypter_decrypt(const ccr_hybrid_decrypter* self,
                                 const uint8_t* ciphertext,
                                 size_t ciphertext_length, uint8_t* plaintext,
                                 size_t plaintext_length, size_t* bytes_written,
                                 ccr_error* error);

/**
 * Returns the size of the plaintext buffer needed for the
 * ccr_hybrid_decrypter_decrypt function.
 */
size_t ccr_hybrid_decrypter_max_plaintext_length(
    const ccr_hybrid_decrypter* self, size_t ciphertext_length);

/**
 * Destructs the ccr_hybrid_decrypter and frees the allocated memory.
 */
void ccr_hybrid_decrypter_free(ccr_hybrid_decrypter* self);

#ifdef __cplusplus
}
#endif

#endif  /* CRUNCHY_INTERNAL_PURE_C_CRYPTO_INTERFACES_H_ */
