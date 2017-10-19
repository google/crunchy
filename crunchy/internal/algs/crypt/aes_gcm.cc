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

#include "crunchy/internal/algs/crypt/aes_gcm.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace crunchy {

namespace {

const size_t kAesGcmNonceLength = 12;
const size_t kAesGcmTagLength = 16;
const size_t kAes128GcmKeyLength = 16;
const size_t kAes256GcmKeyLength = 32;

class AesGcmCrypter : public CrypterBase {
 public:
  Status Encrypt(const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                 size_t aad_length, const uint8_t* plaintext,
                 size_t plaintext_length, uint8_t* ciphertext_and_tag,
                 size_t ciphertext_and_tag_length,
                 size_t* bytes_written) override;

  Status Decrypt(const uint8_t* nonce, size_t nonce_length, const uint8_t* aad,
                 size_t aad_length, const uint8_t* ciphertext_and_tag,
                 size_t ciphertext_and_tag_length, uint8_t* plaintext,
                 size_t plaintext_length, size_t* bytes_written) override;

  size_t nonce_length() const override { return kAesGcmNonceLength; }
  size_t tag_length() const override { return kAesGcmTagLength; }

  Status Init(absl::string_view key, const EVP_AEAD* aead) {
    if (!EVP_AEAD_CTX_init(aead_ctx_.get(), aead,
                           reinterpret_cast<const uint8_t*>(key.data()),
                           key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "AEAD context initialization failed: " << GetOpensslErrors();
    }
    return OkStatus();
  }

 private:
  bssl::ScopedEVP_AEAD_CTX aead_ctx_;
};

Status AesGcmCrypter::Encrypt(const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* aad, size_t aad_length,
                              const uint8_t* plaintext, size_t plaintext_length,
                              uint8_t* ciphertext_and_tag,
                              size_t ciphertext_and_tag_length,
                              size_t* bytes_written) {
  Status status = CheckEncryptInput(
      nonce, nonce_length, aad, aad_length, plaintext, plaintext_length,
      ciphertext_and_tag, ciphertext_and_tag_length, bytes_written);
  if (!status.ok()) {
    return status;
  }
  *bytes_written = 0;
  if (!EVP_AEAD_CTX_seal(aead_ctx_.get(), ciphertext_and_tag, bytes_written,
                         ciphertext_and_tag_length, nonce, nonce_length,
                         plaintext, plaintext_length, aad, aad_length)) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "AEAD seal failed, " << GetOpensslErrors();
  }
  return OkStatus();
}

Status AesGcmCrypter::Decrypt(const uint8_t* nonce, size_t nonce_length,
                              const uint8_t* aad, size_t aad_length,
                              const uint8_t* ciphertext_and_tag,
                              size_t ciphertext_and_tag_length,
                              uint8_t* plaintext, size_t plaintext_length,
                              size_t* bytes_written) {
  Status status = CheckDecryptInput(
      nonce, nonce_length, aad, aad_length, plaintext, plaintext_length,
      ciphertext_and_tag, ciphertext_and_tag_length, bytes_written);
  if (!status.ok()) {
    return status;
  }
  if (nullptr != bytes_written) {
    *bytes_written = 0;
  }
  size_t written_plaintext_length;
  if (!EVP_AEAD_CTX_open(aead_ctx_.get(), plaintext, &written_plaintext_length,
                         plaintext_length, nonce, nonce_length,
                         ciphertext_and_tag, ciphertext_and_tag_length, aad,
                         aad_length)) {
    return InternalErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "AEAD open failed, " << GetOpensslErrors();
  }

  if (nullptr != bytes_written) {
    *bytes_written = written_plaintext_length;
  }
  return OkStatus();
}

class Aes128GcmFactory : public CrypterFactory {
 public:
  size_t GetKeyLength() const override { return kAes128GcmKeyLength; }
  size_t GetNonceLength() const override { return kAesGcmNonceLength; }
  size_t GetTagLength() const override { return kAesGcmTagLength; }

  StatusOr<std::unique_ptr<CrypterInterface>> Make(
      absl::string_view key) const override {
    if (key.size() != GetKeyLength()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Key length was " << key.size() << " expected "
             << GetKeyLength();
    }
    auto crypter = absl::make_unique<AesGcmCrypter>();
    Status status = crypter->Init(key, EVP_aead_aes_128_gcm());
    if (!status.ok()) {
      return status;
    }
    return {std::move(crypter)};
  }
};

class Aes256GcmFactory : public CrypterFactory {
 public:
  size_t GetKeyLength() const override { return kAes256GcmKeyLength; }
  size_t GetNonceLength() const override { return kAesGcmNonceLength; }
  size_t GetTagLength() const override { return kAesGcmTagLength; }

  StatusOr<std::unique_ptr<CrypterInterface>> Make(
      absl::string_view key) const override {
    if (key.size() != GetKeyLength()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "Key length was " << key.size() << " expected "
             << GetKeyLength();
    }
    auto crypter = absl::make_unique<AesGcmCrypter>();
    Status status = crypter->Init(key, EVP_aead_aes_256_gcm());
    if (!status.ok()) {
      return status;
    }
    return {std::move(crypter)};
  }
};

}  // namespace

const CrypterFactory& GetAes128GcmFactory() {
  static const CrypterFactory& factory = *new Aes128GcmFactory();
  return factory;
}

const CrypterFactory& GetAes256GcmFactory() {
  static const CrypterFactory& factory = *new Aes256GcmFactory();
  return factory;
}

}  // namespace crunchy
