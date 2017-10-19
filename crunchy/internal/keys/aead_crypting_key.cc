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

#include "crunchy/internal/keys/aead_crypting_key.h"

#include <stddef.h>
#include <stdint.h>
#include <utility>

#include "absl/memory/memory.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

class AeadCryptingKeyImpl : public AeadCryptingKey {
 public:
  explicit AeadCryptingKeyImpl(std::unique_ptr<CrypterInterface> crypter)
      : crypter_(std::move(crypter)) {}

  StatusOr<std::string> Encrypt(absl::string_view plaintext,
                           absl::string_view aad) const override {
    StringBuffer result(GetNonceLength() +
                        GetMaxCiphertextAndTagLength(plaintext.size()));
    RandBytes(result.data(), GetNonceLength());
    size_t bytes_written = 0;
    auto status = crypter_->Encrypt(
        result.data(), GetNonceLength(),
        reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        result.data() + GetNonceLength(), result.length() - GetNonceLength(),
        &bytes_written);
    if (!status.ok()) {
      return status;
    }
    *result.mutable_limit() = GetNonceLength() + bytes_written;
    return std::move(result.as_string());
  }
  StatusOr<std::string> Decrypt(absl::string_view ciphertext,
                           absl::string_view aad) const override {
    if (ciphertext.size() < GetNonceLength()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "ciphertext is too small to hold a nonce";
    }
    StringBuffer result(GetMaxPlaintextLength(ciphertext.size()) -
                        GetNonceLength());
    const uint8_t* nonce = reinterpret_cast<const uint8_t*>(ciphertext.data());
    auto status = crypter_->Decrypt(
        nonce, GetNonceLength(), reinterpret_cast<const uint8_t*>(aad.data()),
        aad.size(),
        reinterpret_cast<const uint8_t*>(ciphertext.data()) + GetNonceLength(),
        ciphertext.size() - GetNonceLength(), result.data(), result.length(),
        result.mutable_limit());
    if (!status.ok()) {
      return status;
    }
    return std::move(result.as_string());
  }

 private:
  std::unique_ptr<CrypterInterface> crypter_;

  size_t GetNonceLength() const { return crypter_->nonce_length(); }

  size_t GetMaxPlaintextLength(size_t ciphertext_and_tag_length) const {
    return crypter_->max_plaintext_length(ciphertext_and_tag_length);
  }

  size_t GetMaxCiphertextAndTagLength(size_t plaintext_length) const {
    return crypter_->max_ciphertext_and_tag_length(plaintext_length);
  }
};

class AeadCryptingKeyFactoryImpl : public AeadCryptingKeyFactory {
 public:
  explicit AeadCryptingKeyFactoryImpl(const CrypterFactory& factory)
      : factory_(factory) {}

  KeyData CreateRandomKeyData() const override {
    KeyData key_data;
    key_data.set_private_key(RandString(factory_.GetKeyLength()));
    return key_data;
  }
  StatusOr<std::unique_ptr<AeadCryptingKey>> MakeKey(
      const KeyData& key_data) const override {
    if (key_data.private_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.private_key() is empty";
    }
    auto status_or_crypter = factory_.Make(key_data.private_key());
    if (!status_or_crypter.ok()) {
      return status_or_crypter.status();
    }
    return {absl::make_unique<AeadCryptingKeyImpl>(
        std::move(status_or_crypter.ValueOrDie()))};
  }

 private:
  const CrypterFactory& factory_;
};

}  // namespace

std::unique_ptr<AeadCryptingKeyFactory> MakeFactory(
    const CrypterFactory& factory) {
  return {absl::make_unique<AeadCryptingKeyFactoryImpl>(factory)};
}

}  // namespace crunchy
