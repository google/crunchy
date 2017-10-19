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

#include "crunchy/internal/keyset/crypter_factory.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/strip.h"
#include "crunchy/internal/keys/aead_crypting_key.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {
namespace {

class CrypterImpl : public CrunchyCrypter {
 public:
  CrypterImpl(std::vector<std::unique_ptr<AeadCryptingKey>> keys,
              std::vector<std::string> prefices, AeadCryptingKey* primary_key,
              absl::string_view primary_prefix)
      : keys_(std::move(keys)),
        prefices_(std::move(prefices)),
        primary_key_(CRUNCHY_CHECK_NOTNULL(primary_key)),
        primary_prefix_(primary_prefix) {
    CRUNCHY_CHECK_EQ(keys_.size(), prefices_.size());
  }

  virtual StatusOr<std::string> Encrypt(absl::string_view plaintext) const {
    return Encrypt(plaintext, "");
  }
  virtual StatusOr<std::string> Decrypt(absl::string_view ciphertext) const {
    return Decrypt(ciphertext, "");
  }

  virtual StatusOr<std::string> Encrypt(absl::string_view plaintext,
                                   absl::string_view associated_data) const {
    auto status_or_ciphertext =
        primary_key_->Encrypt(plaintext, associated_data);
    if (!status_or_ciphertext.ok()) {
      return status_or_ciphertext.status();
    }
    return StrCat(primary_prefix_, status_or_ciphertext.ValueOrDie());
  }
  virtual StatusOr<std::string> Decrypt(absl::string_view ciphertext,
                                   absl::string_view associated_data) const {
    bool key_found = false;
    Status error_status;
    for (size_t i = 0; i < keys_.size(); i++) {
      absl::string_view crypto_ciphertext = ciphertext;
      if (!absl::ConsumePrefix(&crypto_ciphertext, prefices_[i])) {
        continue;
      }
      key_found = true;
      auto status_or_plaintext =
          keys_[i]->Decrypt(crypto_ciphertext, associated_data);
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
  const std::vector<std::unique_ptr<AeadCryptingKey>> keys_;
  const std::vector<std::string> prefices_;
  const AeadCryptingKey* primary_key_;
  const absl::string_view primary_prefix_;
};

}  // namespace

StatusOr<std::unique_ptr<CrunchyCrypter>> MakeCrunchyCrypter(
    const AeadCryptingKeyRegistry& registry, const Keyset& keyset) {
  std::vector<std::unique_ptr<AeadCryptingKey>> keys;
  std::vector<std::string> prefices;
  for (const Key& key : keyset.key()) {
    auto status_or_key = registry.MakeKey(
        key.metadata().type().google_key_type_label(), key.data());
    if (!status_or_key.ok()) {
      return status_or_key.status();
    }
    keys.push_back(std::move(status_or_key.ValueOrDie()));
    prefices.push_back(key.metadata().prefix());
  }
  if (keyset.primary_key_id() < 0) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Invalid primary key id: " << keyset.primary_key_id();
  }
  if (keys.size() <= static_cast<size_t>(keyset.primary_key_id())) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "primary_key_id is " << keyset.primary_key_id()
           << " but there are only " << keys.size() << " keys";
  }
  AeadCryptingKey* primary_key = keys[keyset.primary_key_id()].get();
  absl::string_view primary_prefix = prefices[keyset.primary_key_id()];

  return {absl::make_unique<CrypterImpl>(std::move(keys), std::move(prefices),
                                         primary_key, primary_prefix)};
}

StatusOr<std::unique_ptr<CrunchyCrypter>> MakeCrunchyCrypter(
    absl::string_view serialized_keyset) {
  const AeadCryptingKeyRegistry& registry = GetAeadCryptingKeyRegistry();
  Keyset keyset;
  if (!keyset.ParseFromArray(serialized_keyset.data(),
                             serialized_keyset.size())) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Couldn't parse keyset";
  }
  return MakeCrunchyCrypter(registry, keyset);
}

}  // namespace crunchy
