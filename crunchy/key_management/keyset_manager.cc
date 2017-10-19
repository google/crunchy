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

#include "crunchy/key_management/keyset_manager.h"

#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/key_management/keyset_enums.pb.h"

namespace crunchy {

const size_t kDefaultPrefixLength = 8;

StatusOr<std::shared_ptr<KeyHandle>> KeysetManager::GenerateAndAddNewKey(
    absl::string_view type_name) {
  return GenerateAndAddNewKey(type_name, RandString(kDefaultPrefixLength));
}

StatusOr<std::shared_ptr<KeyHandle>> KeysetManager::GenerateAndAddNewKey(
    absl::string_view type_name, absl::string_view prefix) {
  StatusOr<std::shared_ptr<KeyHandle>> status_or_key_handle =
      advanced_keyset_manager_->CreateNewKey(type_name, prefix);
  if (!status_or_key_handle.ok()) {
    return status_or_key_handle.status();
  }
  return status_or_key_handle.ValueOrDie();
}

Status KeysetManager::AddNewKey(const std::shared_ptr<KeyHandle>& key_handle) {
  Status add_key_status = advanced_keyset_manager_->AddKey(key_handle);
  if (!add_key_status.ok()) {
    return add_key_status;
  }
  return OkStatus();
}

}  // namespace crunchy
