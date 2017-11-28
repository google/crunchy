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

#include "crunchy/internal/keyset/hybrid_crypter_factory.h"

#include <stddef.h>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/strip.h"
#include "crunchy/internal/keys/hybrid_crypting_key.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/key_management/keyset_handle.h"

namespace crunchy {
namespace {

class HybridEncrypterImpl : public CrunchyHybridEncrypter {
 public:
  HybridEncrypterImpl(std::unique_ptr<HybridEncryptingKey> key,
                      absl::string_view prefix)
      : key_(std::move(key)), prefix_(prefix) {}

  StatusOr<std::string> Encrypt(absl::string_view plaintext) const override {
    auto status_or_ciphertext = key_->Encrypt(plaintext);
    if (!status_or_ciphertext.ok()) {
      return status_or_ciphertext.status();
    }
    return absl::StrCat(prefix_, status_or_ciphertext.ValueOrDie());
  }

 private:
  const std::unique_ptr<HybridEncryptingKey> key_;
  const std::string prefix_;
};

class HybridDecrypterImpl : public CrunchyHybridDecrypter {
 public:
  HybridDecrypterImpl(std::vector<std::unique_ptr<HybridDecryptingKey>> keys,
                      std::vector<std::string> prefices)
      : keys_(std::move(keys)), prefices_(std::move(prefices)) {
    CRUNCHY_CHECK_EQ(keys_.size(), prefices_.size());
  }

  StatusOr<std::string> Decrypt(absl::string_view ciphertext) const override {
    bool key_found = false;
    Status error_status;
    for (size_t i = 0; i < keys_.size(); i++) {
      absl::string_view crypto_ciphertext = ciphertext;
      if (!absl::ConsumePrefix(&crypto_ciphertext, prefices_[i])) {
        continue;
      }
      key_found = true;
      auto status_or_plaintext = keys_[i]->Decrypt(crypto_ciphertext);
      if (status_or_plaintext.ok()) {
        return std::move(status_or_plaintext.ValueOrDie());
      }
      error_status = status_or_plaintext.status();
    }
    if (key_found) {
      return error_status;
    }
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Key not found";
  }

 private:
  const std::vector<std::unique_ptr<HybridDecryptingKey>> keys_;
  const std::vector<std::string> prefices_;
};

}  // namespace

StatusOr<std::unique_ptr<CrunchyHybridEncrypter>> MakeCrunchyHybridEncrypter(
    const HybridCryptingKeyRegistry& registry, const Keyset& keyset) {
  if (keyset.primary_key_id() < 0) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Invalid primary key id: " << keyset.primary_key_id();
  }
  if (keyset.key_size() <= keyset.primary_key_id()) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "primary_key_id is " << keyset.primary_key_id()
           << " but there are only " << keyset.key_size() << " keys";
  }
  const Key& key = keyset.key(keyset.primary_key_id());
  auto status_or_key = registry.MakeHybridEncryptingKey(
      key.metadata().type().crunchy_label(), key.data());
  if (!status_or_key.ok()) {
    return status_or_key.status();
  }
  return {absl::make_unique<HybridEncrypterImpl>(
      std::move(status_or_key.ValueOrDie()), key.metadata().prefix())};
}

StatusOr<std::unique_ptr<CrunchyHybridDecrypter>> MakeCrunchyHybridDecrypter(
    const HybridCryptingKeyRegistry& registry, const Keyset& keyset) {
  if (keyset.key_size() == 0) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "keyset must contain at least one key";
  }
  std::vector<std::unique_ptr<HybridDecryptingKey>> keys;
  std::vector<std::string> prefices;
  for (const Key& key : keyset.key()) {
    auto status_or_key = registry.MakeHybridDecryptingKey(
        key.metadata().type().crunchy_label(), key.data());
    if (!status_or_key.ok()) {
      return status_or_key.status();
    }
    keys.push_back(std::move(status_or_key.ValueOrDie()));
    prefices.push_back(key.metadata().prefix());
  }

  return {absl::make_unique<HybridDecrypterImpl>(std::move(keys),
                                                 std::move(prefices))};
}

}  // namespace crunchy
