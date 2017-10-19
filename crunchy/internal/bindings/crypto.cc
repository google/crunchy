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

#include "crunchy/internal/bindings/crypto.h"

#include <string.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/crunchy_crypter.h"
#include "crunchy/crunchy_hybrid_crypter.h"
#include "crunchy/crunchy_macer.h"
#include "crunchy/crunchy_signer.h"
#include "crunchy/internal/keyset/crypter_factory.h"
#include "crunchy/internal/keyset/hybrid_crypter_factory.h"
#include "crunchy/internal/keyset/macer_factory.h"
#include "crunchy/internal/keyset/signer_factory.h"
#include "crunchy/internal/pure_c/crypto.h"
#include "crunchy/util/status.h"

namespace crunchy {
namespace {

const size_t kMaxEncryptionOverhead = 256;
const size_t kMaxSignatureLength = 1024;

absl::string_view ToStringView(const uint8_t* data, size_t length) {
  return absl::string_view(reinterpret_cast<const char*>(data), length);
}

void set_error(absl::string_view message, ccr_error* error) {
  if (error == nullptr) return;
  error->message = reinterpret_cast<char*>(ccr_malloc(message.size() + 1));
  memcpy(error->message, message.data(), message.size());
  error->message[message.size()] = '\0';
}

struct shim_crypter {
  ccr_crypter base;
  std::unique_ptr<CrunchyCrypter> crypter;
};

int crypter_encrypt(const ccr_crypter* self, const uint8_t* plaintext,
                    size_t plaintext_length, const uint8_t* aad,
                    size_t aad_length, uint8_t* ciphertext,
                    size_t ciphertext_length, size_t* bytes_written,
                    ccr_error* error) {
  const shim_crypter* crypter = reinterpret_cast<const shim_crypter*>(self);
  auto status_or_ciphertext = crypter->crypter->Encrypt(
      ToStringView(plaintext, plaintext_length), ToStringView(aad, aad_length));
  if (!status_or_ciphertext.ok()) {
    set_error(status_or_ciphertext.status().error_message(), error);
    return 0;
  }
  std::string ciphertext_string = std::move(status_or_ciphertext.ValueOrDie());
  if (ciphertext_string.length() > ciphertext_length) {
    set_error(absl::StrCat("ciphertext buffer is too short ", ciphertext_length,
                           " given ", ciphertext_string.length(), " needed"),
              error);
    return 0;
  }
  memcpy(ciphertext, ciphertext_string.data(), ciphertext_string.length());
  *bytes_written = ciphertext_string.length();
  return 1;
}

size_t crypter_max_ciphertext_length(const ccr_crypter* self,
                                     size_t plaintext_length) {
  return plaintext_length + kMaxEncryptionOverhead;
}

int crypter_decrypt(const ccr_crypter* self, const uint8_t* ciphertext,
                    size_t ciphertext_length, const uint8_t* aad,
                    size_t aad_length, uint8_t* plaintext,
                    size_t plaintext_length, size_t* bytes_written,
                    ccr_error* error) {
  const shim_crypter* crypter = reinterpret_cast<const shim_crypter*>(self);
  auto status_or_plaintext =
      crypter->crypter->Decrypt(ToStringView(ciphertext, ciphertext_length),
                                ToStringView(aad, aad_length));
  if (!status_or_plaintext.ok()) {
    set_error(status_or_plaintext.status().error_message(), error);
    return 0;
  }
  std::string plaintext_string = std::move(status_or_plaintext.ValueOrDie());
  if (plaintext_string.length() > plaintext_length) {
    set_error(absl::StrCat("plaintext buffer is too short ", plaintext_length,
                           " given ", plaintext_string.length(), " needed"),
              error);
    return 0;
  }
  memcpy(plaintext, plaintext_string.data(), plaintext_string.length());
  *bytes_written = plaintext_string.length();
  return 1;
}

size_t crypter_max_plaintext_length(const ccr_crypter* self,
                                    size_t ciphertext_length) {
  return ciphertext_length;
}

void crypter_free(ccr_crypter* self) {
  shim_crypter* crypter = reinterpret_cast<shim_crypter*>(self);
  crypter->crypter.reset(nullptr);
  ccr_free(self);
}

ccr_crypter_vtable crypter_vtable = {
    crypter_encrypt, crypter_max_ciphertext_length,
    crypter_decrypt, crypter_max_plaintext_length,
    crypter_free,
};

struct shim_mac {
  ccr_macer base;
  std::unique_ptr<CrunchyMacer> mac;
};

int mac_sign(const ccr_macer* self, const uint8_t* message,
             size_t message_length, uint8_t* signature, size_t signature_length,
             size_t* bytes_written, ccr_error* error) {
  const shim_mac* mac = reinterpret_cast<const shim_mac*>(self);
  auto status_or_signature =
      mac->mac->Sign(ToStringView(message, message_length));
  if (!status_or_signature.ok()) {
    set_error(status_or_signature.status().error_message(), error);
    return 0;
  }
  std::string signature_string = std::move(status_or_signature.ValueOrDie());
  if (signature_string.length() > signature_length) {
    set_error(absl::StrCat("signature buffer is too short ", signature_length,
                           " given ", signature_string.length(), " needed"),
              error);
    return 0;
  }
  memcpy(signature, signature_string.data(), signature_string.length());
  *bytes_written = signature_string.length();
  return 1;
}

size_t mac_max_signature_length(const ccr_macer* self) {
  return kMaxSignatureLength;
}

int mac_verify(const ccr_macer* self, const uint8_t* message,
               size_t message_length, const uint8_t* signature,
               size_t signature_length, ccr_error* error) {
  const shim_mac* mac = reinterpret_cast<const shim_mac*>(self);
  Status status = mac->mac->Verify(ToStringView(message, message_length),
                                   ToStringView(signature, signature_length));
  if (!status.ok()) {
    set_error(status.error_message(), error);
    return 0;
  }
  return 1;
}

void mac_free(ccr_macer* self) {
  shim_mac* mac = reinterpret_cast<shim_mac*>(self);
  mac->mac.reset(nullptr);
  ccr_free(self);
}

ccr_macer_vtable mac_vtable = {
    mac_sign, mac_max_signature_length, mac_verify, mac_free,
};

struct shim_signer {
  ccr_signer base;
  std::unique_ptr<CrunchySigner> signer;
};

int signer_sign(const ccr_signer* self, const uint8_t* message,
                size_t message_length, uint8_t* signature,
                size_t signature_length, size_t* bytes_written,
                ccr_error* error) {
  const shim_signer* signer = reinterpret_cast<const shim_signer*>(self);
  auto status_or_signature =
      signer->signer->Sign(ToStringView(message, message_length));
  if (!status_or_signature.ok()) {
    set_error(status_or_signature.status().error_message(), error);
    return 0;
  }
  std::string signature_string = std::move(status_or_signature.ValueOrDie());
  if (signature_string.length() > signature_length) {
    set_error(absl::StrCat("signature buffer is too short ", signature_length,
                           " given ", signature_string.length(), " needed"),
              error);
    return 0;
  }
  memcpy(signature, signature_string.data(), signature_string.length());
  *bytes_written = signature_string.length();
  return 1;
}

size_t signer_max_signature_length(const ccr_signer* self) {
  return kMaxSignatureLength;
}

void signer_free(ccr_signer* self) {
  shim_signer* signer = reinterpret_cast<shim_signer*>(self);
  signer->signer.reset(nullptr);
  ccr_free(self);
}

ccr_signer_vtable signer_vtable = {
    signer_sign, signer_max_signature_length, signer_free,
};

struct shim_verifier {
  ccr_verifier base;
  std::unique_ptr<CrunchyVerifier> verifier;
};

int verifier_verify(const ccr_verifier* self, const uint8_t* message,
                    size_t message_length, const uint8_t* signature,
                    size_t signature_length, ccr_error* error) {
  const shim_verifier* verifier = reinterpret_cast<const shim_verifier*>(self);
  Status status =
      verifier->verifier->Verify(ToStringView(message, message_length),
                                 ToStringView(signature, signature_length));
  if (!status.ok()) {
    set_error(status.error_message(), error);
    return 0;
  }
  return 1;
}

void verifier_free(ccr_verifier* self) {
  shim_verifier* verifier = reinterpret_cast<shim_verifier*>(self);
  verifier->verifier.reset(nullptr);
  ccr_free(self);
}

ccr_verifier_vtable verifier_vtable = {
    verifier_verify, verifier_free,
};

struct shim_hybrid_encrypter {
  ccr_hybrid_encrypter base;
  std::unique_ptr<CrunchyHybridEncrypter> hybrid_encrypter;
};

int hybrid_encrypter_encrypt(const ccr_hybrid_encrypter* self,
                             const uint8_t* plaintext, size_t plaintext_length,
                             uint8_t* ciphertext, size_t ciphertext_length,
                             size_t* bytes_written, ccr_error* error) {
  const shim_hybrid_encrypter* hybrid_encrypter =
      reinterpret_cast<const shim_hybrid_encrypter*>(self);
  auto status_or_ciphertext = hybrid_encrypter->hybrid_encrypter->Encrypt(
      ToStringView(plaintext, plaintext_length));
  if (!status_or_ciphertext.ok()) {
    set_error(status_or_ciphertext.status().error_message(), error);
    return 0;
  }
  std::string ciphertext_string = std::move(status_or_ciphertext.ValueOrDie());
  if (ciphertext_string.length() > ciphertext_length) {
    set_error(absl::StrCat("ciphertext buffer is too short ", ciphertext_length,
                           " given ", ciphertext_string.length(), " needed"),
              error);
    return 0;
  }
  memcpy(ciphertext, ciphertext_string.data(), ciphertext_string.length());
  *bytes_written = ciphertext_string.length();
  return 1;
}

size_t hybrid_encrypter_max_ciphertext_length(const ccr_hybrid_encrypter* self,
                                              size_t plaintext_length) {
  return plaintext_length + kMaxEncryptionOverhead;
}

void hybrid_encrypter_free(ccr_hybrid_encrypter* self) {
  shim_hybrid_encrypter* hybrid_encrypter =
      reinterpret_cast<shim_hybrid_encrypter*>(self);
  hybrid_encrypter->hybrid_encrypter.reset(nullptr);
  ccr_free(self);
}

ccr_hybrid_encrypter_vtable hybrid_encrypter_vtable = {
    hybrid_encrypter_encrypt, hybrid_encrypter_max_ciphertext_length,
    hybrid_encrypter_free,
};

struct shim_hybrid_decrypter {
  ccr_hybrid_decrypter base;
  std::unique_ptr<CrunchyHybridDecrypter> hybrid_decrypter;
};

int hybrid_decrypter_decrypt(const ccr_hybrid_decrypter* self,
                             const uint8_t* ciphertext,
                             size_t ciphertext_length, uint8_t* plaintext,
                             size_t plaintext_length, size_t* bytes_written,
                             ccr_error* error) {
  const shim_hybrid_decrypter* hybrid_decrypter =
      reinterpret_cast<const shim_hybrid_decrypter*>(self);
  auto status_or_plaintext = hybrid_decrypter->hybrid_decrypter->Decrypt(
      ToStringView(ciphertext, ciphertext_length));
  if (!status_or_plaintext.ok()) {
    set_error(status_or_plaintext.status().error_message(), error);
    return 0;
  }
  std::string plaintext_string = std::move(status_or_plaintext.ValueOrDie());
  if (plaintext_string.length() > plaintext_length) {
    set_error(absl::StrCat("plaintext buffer is too short ", plaintext_length,
                           " given ", plaintext_string.length(), " needed"),
              error);
    return 0;
  }
  memcpy(plaintext, plaintext_string.data(), plaintext_string.length());
  *bytes_written = plaintext_string.length();
  return 1;
}

size_t hybrid_decrypter_max_plaintext_length(const ccr_hybrid_decrypter* self,
                                             size_t ciphertext_length) {
  return ciphertext_length;
}

void hybrid_decrypter_free(ccr_hybrid_decrypter* self) {
  shim_hybrid_decrypter* hybrid_decrypter =
      reinterpret_cast<shim_hybrid_decrypter*>(self);
  hybrid_decrypter->hybrid_decrypter.reset(nullptr);
  ccr_free(self);
}

ccr_hybrid_decrypter_vtable hybrid_decrypter_vtable = {
    hybrid_decrypter_decrypt, hybrid_decrypter_max_plaintext_length,
    hybrid_decrypter_free,
};

ccr_crypter* ConstructCrypter(const uint8_t* keyset_bytes, size_t keyset_length,
                              ccr_error* error) {
  if (keyset_bytes == nullptr) {
    set_error("keyset_bytes is null", error);
    return nullptr;
  }
  auto status_or_crypter =
      MakeCrunchyCrypter(ToStringView(keyset_bytes, keyset_length));
  if (!status_or_crypter.ok()) {
    set_error(status_or_crypter.status().error_message(), error);
    return nullptr;
  }

  shim_crypter* result =
      reinterpret_cast<shim_crypter*>(ccr_malloc(sizeof(*result)));
  memset(result, 0, sizeof(*result));
  result->base.vtable = &crypter_vtable;
  result->crypter = std::move(status_or_crypter.ValueOrDie());

  return reinterpret_cast<ccr_crypter*>(result);
}

ccr_macer* ConstructMac(const uint8_t* keyset_bytes, size_t keyset_length,
                        ccr_error* error) {
  if (keyset_bytes == nullptr) {
    set_error("keyset_bytes is null", error);
    return nullptr;
  }
  auto status_or_mac =
      MakeCrunchyMacer(ToStringView(keyset_bytes, keyset_length));
  if (!status_or_mac.ok()) {
    set_error(status_or_mac.status().error_message(), error);
    return nullptr;
  }

  shim_mac* result = reinterpret_cast<shim_mac*>(ccr_malloc(sizeof(*result)));
  memset(result, 0, sizeof(*result));
  result->base.vtable = &mac_vtable;
  result->mac = std::move(status_or_mac.ValueOrDie());

  return reinterpret_cast<ccr_macer*>(result);
}

ccr_signer* ConstructSigner(const uint8_t* keyset_bytes, size_t keyset_length,
                            ccr_error* error) {
  if (keyset_bytes == nullptr) {
    set_error("keyset_bytes is null", error);
    return nullptr;
  }
  auto status_or_signer =
      MakeCrunchySigner(ToStringView(keyset_bytes, keyset_length));
  if (!status_or_signer.ok()) {
    set_error(status_or_signer.status().error_message(), error);
    return nullptr;
  }

  shim_signer* result =
      reinterpret_cast<shim_signer*>(ccr_malloc(sizeof(*result)));
  memset(result, 0, sizeof(*result));
  result->base.vtable = &signer_vtable;
  result->signer = std::move(status_or_signer.ValueOrDie());

  return reinterpret_cast<ccr_signer*>(result);
}

ccr_verifier* ConstructVerifier(const uint8_t* keyset_bytes,
                                size_t keyset_length, ccr_error* error) {
  if (keyset_bytes == nullptr) {
    set_error("keyset_bytes is null", error);
    return nullptr;
  }
  auto status_or_verifier =
      MakeCrunchyVerifier(ToStringView(keyset_bytes, keyset_length));
  if (!status_or_verifier.ok()) {
    set_error(status_or_verifier.status().error_message(), error);
    return nullptr;
  }

  shim_verifier* result =
      reinterpret_cast<shim_verifier*>(ccr_malloc(sizeof(*result)));
  memset(result, 0, sizeof(*result));
  result->base.vtable = &verifier_vtable;
  result->verifier = std::move(status_or_verifier.ValueOrDie());

  return reinterpret_cast<ccr_verifier*>(result);
}

ccr_hybrid_encrypter* ConstructHybridEncrypter(const uint8_t* keyset_bytes,
                                               size_t keyset_length,
                                               ccr_error* error) {
  if (keyset_bytes == nullptr) {
    set_error("keyset_bytes is null", error);
    return nullptr;
  }
  auto status_or_hybrid_encrypter =
      MakeCrunchyHybridEncrypter(ToStringView(keyset_bytes, keyset_length));
  if (!status_or_hybrid_encrypter.ok()) {
    set_error(status_or_hybrid_encrypter.status().error_message(), error);
    return nullptr;
  }

  shim_hybrid_encrypter* result =
      reinterpret_cast<shim_hybrid_encrypter*>(ccr_malloc(sizeof(*result)));
  memset(result, 0, sizeof(*result));
  result->base.vtable = &hybrid_encrypter_vtable;
  result->hybrid_encrypter = std::move(status_or_hybrid_encrypter.ValueOrDie());

  return reinterpret_cast<ccr_hybrid_encrypter*>(result);
}

ccr_hybrid_decrypter* ConstructHybridDecrypter(const uint8_t* keyset_bytes,
                                               size_t keyset_length,
                                               ccr_error* error) {
  if (keyset_bytes == nullptr) {
    set_error("keyset_bytes is null", error);
    return nullptr;
  }
  auto status_or_hybrid_decrypter =
      MakeCrunchyHybridDecrypter(ToStringView(keyset_bytes, keyset_length));
  if (!status_or_hybrid_decrypter.ok()) {
    set_error(status_or_hybrid_decrypter.status().error_message(), error);
    return nullptr;
  }

  shim_hybrid_decrypter* result =
      reinterpret_cast<shim_hybrid_decrypter*>(ccr_malloc(sizeof(*result)));
  memset(result, 0, sizeof(*result));
  result->base.vtable = &hybrid_decrypter_vtable;
  result->hybrid_decrypter = std::move(status_or_hybrid_decrypter.ValueOrDie());

  return reinterpret_cast<ccr_hybrid_decrypter*>(result);
}

}  // namespace
}  // namespace crunchy

#ifdef __cplusplus
extern "C" {
#endif

ccr_crypter* ccr_crypter_new_from_serialized_keyset(const uint8_t* keyset_bytes,
                                                    size_t keyset_length,
                                                    ccr_error* error) {
  return crunchy::ConstructCrypter(keyset_bytes, keyset_length, error);
}

ccr_macer* ccr_macer_new_from_serialized_keyset(const uint8_t* keyset_bytes,
                                                size_t keyset_length,
                                                ccr_error* error) {
  return crunchy::ConstructMac(keyset_bytes, keyset_length, error);
}

ccr_signer* ccr_signer_new_from_serialized_keyset(const uint8_t* keyset_bytes,
                                                  size_t keyset_length,
                                                  ccr_error* error) {
  return crunchy::ConstructSigner(keyset_bytes, keyset_length, error);
}

ccr_verifier* ccr_verifier_new_from_serialized_keyset(
    const uint8_t* keyset_bytes, size_t keyset_length, ccr_error* error) {
  return crunchy::ConstructVerifier(keyset_bytes, keyset_length, error);
}

ccr_hybrid_encrypter* ccr_hybrid_encrypter_new_from_serialized_keyset(
    const uint8_t* keyset_bytes, size_t keyset_length, ccr_error* error) {
  return crunchy::ConstructHybridEncrypter(keyset_bytes, keyset_length, error);
}

ccr_hybrid_decrypter* ccr_hybrid_decrypter_new_from_serialized_keyset(
    const uint8_t* keyset_bytes, size_t keyset_length, ccr_error* error) {
  return crunchy::ConstructHybridDecrypter(keyset_bytes, keyset_length, error);
}

#ifdef __cplusplus
}
#endif
