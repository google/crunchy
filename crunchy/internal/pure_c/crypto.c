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

#include "crunchy/internal/pure_c/crypto.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static void set_error(const char* message, ccr_error* error) {
  if (error == NULL) return;
  error->message = (char*)ccr_malloc(strlen(message) + 1);
  memcpy(error->message, message, strlen(message) + 1);
}

void* ccr_malloc(size_t length) {
  void* ptr = malloc(length);
  assert(ptr != NULL);
  return ptr;
}

void ccr_free(void* ptr) { free(ptr); }

void ccr_error_init(ccr_error* self) { memset(self, 0, sizeof(*self)); }
void ccr_error_cleanup(ccr_error* self) {
  free(self->message);
  self->message = NULL;
}

int ccr_crypter_encrypt(const ccr_crypter* self,
                             const uint8_t* plaintext, size_t plaintext_length,
                             const uint8_t* associated_data,
                             size_t associated_data_length, uint8_t* ciphertext,
                             size_t ciphertext_length, size_t* bytes_written,
                             ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_crypter_encrypt: self is null", error);
    return 0;
  }
  if (plaintext == NULL && plaintext_length > 0) {
    set_error("ccr_crypter_encrypt: plaintext buffer is null", error);
    return 0;
  }
  if (associated_data == NULL && associated_data_length > 0) {
    set_error("ccr_crypter_encrypt: associated_data buffer is null", error);
    return 0;
  }
  if (ciphertext == NULL) {
    set_error("ccr_crypter_encrypt: ciphertext buffer is null", error);
    return 0;
  }
  if (bytes_written == NULL) {
    set_error("ccr_crypter_encrypt: bytes_written is null", error);
    return 0;
  }
  return self->vtable->encrypt(self, plaintext, plaintext_length,
                               associated_data, associated_data_length,
                               ciphertext, ciphertext_length, bytes_written,
                               error);
}

size_t ccr_crypter_max_ciphertext_length(const ccr_crypter* self,
                                              size_t plaintext_length) {
  return self->vtable->max_ciphertext_length(self, plaintext_length);
}

int ccr_crypter_decrypt(const ccr_crypter* self,
                             const uint8_t* ciphertext,
                             size_t ciphertext_length,
                             const uint8_t* associated_data,
                             size_t associated_data_length, uint8_t* plaintext,
                             size_t plaintext_length, size_t* bytes_written,
                             ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_crypter_decrypt: self is null", error);
    return 0;
  }
  if (plaintext == NULL && plaintext_length > 0) {
    set_error("ccr_crypter_decrypt: plaintext buffer is null", error);
    return 0;
  }
  if (associated_data == NULL && associated_data_length > 0) {
    set_error("ccr_crypter_decrypt: associated_data buffer is null", error);
    return 0;
  }
  if (ciphertext == NULL) {
    set_error("ccr_crypter_decrypt: ciphertext buffer is null", error);
    return 0;
  }
  if (bytes_written == NULL) {
    set_error("ccr_crypter_decrypt: bytes_written is null", error);
    return 0;
  }
  return self->vtable->decrypt(self, ciphertext, ciphertext_length,
                               associated_data, associated_data_length,
                               plaintext, plaintext_length, bytes_written,
                               error);
}

size_t ccr_crypter_max_plaintext_length(const ccr_crypter* self,
                                        size_t ciphertext_length) {
  return self->vtable->max_plaintext_length(self, ciphertext_length);
}

void ccr_crypter_free(ccr_crypter* self) {
  if (self == NULL) return;
  self->vtable->free(self);
}

int ccr_macer_sign(const ccr_macer* self, const uint8_t* message,
                   size_t message_length, uint8_t* signature,
                   size_t signature_length, size_t* bytes_written,
                   ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_macer_sign: self is null", error);
    return 0;
  }
  if (message == NULL) {
    set_error("ccr_macer_sign: message buffer is null", error);
    return 0;
  }
  if (signature == NULL) {
    set_error("ccr_macer_sign: signature buffer is null", error);
    return 0;
  }
  if (bytes_written == NULL) {
    set_error("ccr_macer_sign: bytes_written is null", error);
    return 0;
  }
  return self->vtable->sign(self, message, message_length, signature,
                            signature_length, bytes_written, error);
}

size_t ccr_macer_max_signature_length(const ccr_macer* self) {
  return self->vtable->max_signature_length(self);
}

int ccr_macer_verify(const ccr_macer* self, const uint8_t* message,
                     size_t message_length, const uint8_t* signature,
                     size_t signature_length, ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_macer_verify: self is null", error);
    return 0;
  }
  if (message == NULL) {
    set_error("ccr_macer_verify: message buffer is null", error);
    return 0;
  }
  if (signature == NULL) {
    set_error("ccr_macer_verify: signature buffer is null", error);
    return 0;
  }
  return self->vtable->verify(self, message, message_length, signature,
                              signature_length, error);
}

void ccr_macer_free(ccr_macer* self) {
  if (self == NULL) return;
  self->vtable->free(self);
}

int ccr_signer_sign(const ccr_signer* self, const uint8_t* message,
                    size_t message_length, uint8_t* signature,
                    size_t signature_length, size_t* bytes_written,
                    ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_signer_sign: self is null", error);
    return 0;
  }
  if (message == NULL) {
    set_error("ccr_signer_sign: message buffer is null", error);
    return 0;
  }
  if (signature == NULL) {
    set_error("ccr_signer_sign: signature buffer is null", error);
    return 0;
  }
  if (bytes_written == NULL) {
    set_error("ccr_signer_sign: bytes_written is null", error);
    return 0;
  }
  return self->vtable->sign(self, message, message_length, signature,
                            signature_length, bytes_written, error);
}

size_t ccr_signer_max_signature_length(const ccr_signer* self) {
  return self->vtable->max_signature_length(self);
}

void ccr_signer_free(ccr_signer* self) {
  if (self == NULL) return;
  self->vtable->free(self);
}

int ccr_verifier_verify(const ccr_verifier* self, const uint8_t* message,
                        size_t message_length, const uint8_t* signature,
                        size_t signature_length, ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_verifier_verify: self is null", error);
    return 0;
  }
  if (message == NULL) {
    set_error("ccr_verifier_verify: message buffer is null", error);
    return 0;
  }
  if (signature == NULL) {
    set_error("ccr_verifier_verify: signature buffer is null", error);
    return 0;
  }
  return self->vtable->verify(self, message, message_length, signature,
                              signature_length, error);
}

void ccr_verifier_free(ccr_verifier* self) {
  if (self == NULL) return;
  self->vtable->free(self);
}

int ccr_hybrid_encrypter_encrypt(const ccr_hybrid_encrypter* self,
                                 const uint8_t* plaintext,
                                 size_t plaintext_length, uint8_t* ciphertext,
                                 size_t ciphertext_length,
                                 size_t* bytes_written, ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_hybrid_encrypter_encrypt: self is null", error);
    return 0;
  }
  if (plaintext == NULL) {
    set_error("ccr_hybrid_encrypter_encrypt: plaintext buffer is null", error);
    return 0;
  }
  if (ciphertext == NULL) {
    set_error("ccr_hybrid_encrypter_encrypt: ciphertext buffer is null", error);
    return 0;
  }
  if (bytes_written == NULL) {
    set_error("ccr_hybrid_encrypter_encrypt: bytes_written is null", error);
    return 0;
  }
  return self->vtable->encrypt(self, plaintext, plaintext_length, ciphertext,
                               ciphertext_length, bytes_written, error);
}

size_t ccr_hybrid_encrypter_max_ciphertext_length(
    const ccr_hybrid_encrypter* self, size_t plaintext_length) {
  return self->vtable->max_ciphertext_length(self, plaintext_length);
}

void ccr_hybrid_encrypter_free(ccr_hybrid_encrypter* self) {
  if (self == NULL) return;
  self->vtable->free(self);
}

int ccr_hybrid_decrypter_decrypt(const ccr_hybrid_decrypter* self,
                                 const uint8_t* ciphertext,
                                 size_t ciphertext_length, uint8_t* plaintext,
                                 size_t plaintext_length, size_t* bytes_written,
                                 ccr_error* error) {
  if (self == NULL) {
    set_error("ccr_hybrid_decrypter_decrypt: self is null", error);
    return 0;
  }
  if (plaintext == NULL) {
    set_error("ccr_hybrid_decrypter_decrypt: plaintext buffer is null", error);
    return 0;
  }
  if (ciphertext == NULL) {
    set_error("ccr_hybrid_decrypter_decrypt: ciphertext buffer is null", error);
    return 0;
  }
  if (bytes_written == NULL) {
    set_error("ccr_hybrid_decrypter_decrypt: bytes_written is null", error);
    return 0;
  }
  return self->vtable->decrypt(self, ciphertext, ciphertext_length, plaintext,
                               plaintext_length, bytes_written, error);
}

size_t ccr_hybrid_decrypter_max_plaintext_length(
    const ccr_hybrid_decrypter* self, size_t ciphertext_length) {
  return self->vtable->max_plaintext_length(self, ciphertext_length);
}

void ccr_hybrid_decrypter_free(ccr_hybrid_decrypter* self) {
  if (self == NULL) return;
  self->vtable->free(self);
}

#ifdef __cplusplus
}
#endif
