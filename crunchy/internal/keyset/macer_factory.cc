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

#include "crunchy/internal/keyset/macer_factory.h"

#include <stddef.h>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/strip.h"
#include "crunchy/internal/keys/macing_key.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"

namespace crunchy {
namespace {

class MacerImpl : public CrunchyMacer {
 public:
  MacerImpl(std::vector<std::unique_ptr<MacingKey>> keys,
            std::vector<std::string> prefices, MacingKey* primary_key,
            absl::string_view primary_prefix)
      : keys_(std::move(keys)),
        prefices_(std::move(prefices)),
        primary_key_(CRUNCHY_CHECK_NOTNULL(primary_key)),
        primary_prefix_(primary_prefix) {
    CRUNCHY_CHECK_EQ(keys_.size(), prefices_.size());
  }

  StatusOr<std::string> Sign(absl::string_view message) const override {
    auto status_or_signature = primary_key_->Sign(message);
    if (!status_or_signature.ok()) {
      return status_or_signature.status();
    }
    return absl::StrCat(primary_prefix_, status_or_signature.ValueOrDie());
  }

  Status Verify(absl::string_view message,
                absl::string_view signature) const override {
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
  const std::vector<std::unique_ptr<MacingKey>> keys_;
  const std::vector<std::string> prefices_;
  const MacingKey* primary_key_;
  const absl::string_view primary_prefix_;
};

}  // namespace

StatusOr<std::unique_ptr<CrunchyMacer>> MakeCrunchyMacer(
    const MacingKeyRegistry& registry, const Keyset& keyset) {
  std::vector<std::unique_ptr<MacingKey>> keys;
  std::vector<std::string> prefices;
  for (const Key& key : keyset.key()) {
    auto status_or_key =
        registry.MakeKey(key.metadata().type().crunchy_label(), key.data());
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
  MacingKey* primary_key = keys[keyset.primary_key_id()].get();
  absl::string_view primary_prefix = prefices[keyset.primary_key_id()];

  return {absl::make_unique<MacerImpl>(std::move(keys), std::move(prefices),
                                       primary_key, primary_prefix)};
}

}  // namespace crunchy
