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

#include "crunchy/internal/keyset/signer_factory.h"

#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/strip.h"
#include "crunchy/internal/keys/signing_key.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/key_management/keyset_handle.h"

namespace crunchy {
namespace {

class SignerImpl : public CrunchySigner {
 public:
  SignerImpl(std::unique_ptr<SigningKey> key, absl::string_view prefix)
      : key_(std::move(key)), prefix_(prefix) {}

  virtual StatusOr<std::string> Sign(absl::string_view message) const {
    auto status_or_signature = key_->Sign(message);
    if (!status_or_signature.ok()) {
      return status_or_signature.status();
    }
    return absl::StrCat(prefix_, status_or_signature.ValueOrDie());
  }

 private:
  const std::unique_ptr<SigningKey> key_;
  const std::string prefix_;
};

class VerifierImpl : public CrunchyVerifier {
 public:
  VerifierImpl(std::vector<std::unique_ptr<VerifyingKey>> keys,
               std::vector<std::string> prefices)
      : keys_(std::move(keys)), prefices_(std::move(prefices)) {
    CRUNCHY_CHECK_EQ(keys_.size(), prefices_.size());
  }

  virtual Status Verify(absl::string_view message,
                        absl::string_view signature) const {
    bool key_found = false;
    Status error_status;
    for (size_t i = 0; i < keys_.size(); i++) {
      absl::string_view crypto_signature = signature;
      if (!absl::ConsumePrefix(&crypto_signature, prefices_[i])) {
        continue;
      }
      key_found = true;
      error_status = keys_[i]->Verify(message, crypto_signature);
      if (error_status.ok()) {
        return OkStatus();
      }
    }
    if (key_found) {
      return error_status;
    }
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Key not found";
  }

 private:
  const std::vector<std::unique_ptr<VerifyingKey>> keys_;
  const std::vector<std::string> prefices_;
};

}  // namespace

StatusOr<std::unique_ptr<CrunchySigner>> MakeCrunchySigner(
    const SigningKeyRegistry& registry, const Keyset& keyset) {
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
  auto status_or_key = registry.MakeSigningKey(
      key.metadata().type().google_key_type_label(), key.data());
  if (!status_or_key.ok()) {
    return status_or_key.status();
  }
  return {absl::make_unique<SignerImpl>(std::move(status_or_key.ValueOrDie()),
                                        key.metadata().prefix())};
}

StatusOr<std::unique_ptr<CrunchyVerifier>> MakeCrunchyVerifier(
    const SigningKeyRegistry& registry, const Keyset& keyset) {
  if (keyset.key_size() == 0) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "keyset must contain at least one key";
  }
  std::vector<std::unique_ptr<VerifyingKey>> keys;
  std::vector<std::string> prefices;
  for (const Key& key : keyset.key()) {
    auto status_or_key = registry.MakeVerifyingKey(
        key.metadata().type().google_key_type_label(), key.data());
    if (!status_or_key.ok()) {
      return status_or_key.status();
    }
    keys.push_back(std::move(status_or_key.ValueOrDie()));
    prefices.push_back(key.metadata().prefix());
  }

  return {
      absl::make_unique<VerifierImpl>(std::move(keys), std::move(prefices))};
}

StatusOr<std::unique_ptr<CrunchySigner>> MakeCrunchySigner(
    absl::string_view serialized_keyset) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  Keyset keyset;
  if (!keyset.ParseFromArray(serialized_keyset.data(),
                             serialized_keyset.size())) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Couldn't parse keyset";
  }
  return MakeCrunchySigner(registry, keyset);
}

StatusOr<std::unique_ptr<CrunchyVerifier>> MakeCrunchyVerifier(
    absl::string_view serialized_keyset) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  Keyset keyset;
  if (!keyset.ParseFromArray(serialized_keyset.data(),
                             serialized_keyset.size())) {
    return InvalidArgumentErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Couldn't parse keyset";
  }
  return MakeCrunchyVerifier(registry, keyset);
}

}  // namespace crunchy
