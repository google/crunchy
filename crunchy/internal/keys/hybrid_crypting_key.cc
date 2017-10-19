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

#include "crunchy/internal/keys/hybrid_crypting_key.h"

#include <utility>

#include "absl/memory/memory.h"

namespace crunchy {

namespace {

class HybridEncryptingKeyImpl : public HybridEncryptingKey {
 public:
  explicit HybridEncryptingKeyImpl(
      std::unique_ptr<HybridEncrypterInterface> hybrid_encrypter)
      : hybrid_encrypter_(std::move(hybrid_encrypter)) {}
  StatusOr<std::string> Encrypt(absl::string_view plaintext) const override {
    return hybrid_encrypter_->Encrypt(plaintext);
  }

 private:
  std::unique_ptr<HybridEncrypterInterface> hybrid_encrypter_;
};

class HybridDecryptingKeyImpl : public HybridDecryptingKey {
 public:
  explicit HybridDecryptingKeyImpl(
      std::unique_ptr<HybridDecrypterInterface> hybrid_decrypter)
      : hybrid_decrypter_(std::move(hybrid_decrypter)) {}
  StatusOr<std::string> Decrypt(absl::string_view ciphertext) const override {
    return hybrid_decrypter_->Decrypt(ciphertext);
  }

 private:
  std::unique_ptr<HybridDecrypterInterface> hybrid_decrypter_;
};

class HybridCryptingKeyFactoryImpl : public HybridCryptingKeyFactory {
 public:
  explicit HybridCryptingKeyFactoryImpl(const HybridCrypterFactory& factory)
      : factory_(factory) {}

  StatusOr<KeyData> CreateRandomPrivateKeyData() const override {
    KeyData key_data;
    Status status = factory_.NewKeypair(key_data.mutable_public_key(),
                                        key_data.mutable_private_key());
    if (!status.ok()) {
      return status;
    }
    return key_data;
  }
  StatusOr<KeyData> CreatePublicKeyData(
      const KeyData& key_data) const override {
    KeyData result = key_data;
    if (result.public_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.public_key() is empty";
    }
    result.clear_private_key();
    return result;
  }
  StatusOr<std::unique_ptr<HybridEncryptingKey>> MakeHybridEncryptingKey(
      const KeyData& key_data) const override {
    if (!key_data.private_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.private_key() is non-empty";
    }
    if (key_data.public_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.public_key() is empty";
    }
    auto status_or_hybrid_encrypter =
        factory_.MakeHybridEncrypter(key_data.public_key());
    if (!status_or_hybrid_encrypter.ok()) {
      return status_or_hybrid_encrypter.status();
    }
    return {absl::make_unique<HybridEncryptingKeyImpl>(
        std::move(status_or_hybrid_encrypter.ValueOrDie()))};
  }
  StatusOr<std::unique_ptr<HybridDecryptingKey>> MakeHybridDecryptingKey(
      const KeyData& key_data) const override {
    if (key_data.private_key().empty()) {
      return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
             << "key_data.private_key() is empty";
    }
    auto status_or_hybrid_decrypter =
        factory_.MakeHybridDecrypter(key_data.private_key());
    if (!status_or_hybrid_decrypter.ok()) {
      return status_or_hybrid_decrypter.status();
    }
    return {absl::make_unique<HybridDecryptingKeyImpl>(
        std::move(status_or_hybrid_decrypter.ValueOrDie()))};
  }

 private:
  const HybridCrypterFactory& factory_;
};

}  // namespace

std::unique_ptr<HybridCryptingKeyFactory> MakeFactory(
    const HybridCrypterFactory& factory) {
  return {absl::make_unique<HybridCryptingKeyFactoryImpl>(factory)};
}

}  // namespace crunchy
