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

#include "crunchy/key_management/internal/advanced_keyset_manager.h"

#include <memory>
#include <string>

#include "absl/strings/str_cat.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/internal/keyset/aead_crypting_key_registry.h"
#include "crunchy/internal/keyset/hybrid_crypting_key_registry.h"
#include "crunchy/internal/keyset/macing_key_registry.h"
#include "crunchy/internal/keyset/signing_key_registry.h"
#include "crunchy/key_management/keyset_enums.pb.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

StatusOr<KeyData> KeyDataFromKeyLabel(const absl::string_view key_label) {
  if (key_label == "aes-128-gcm") {
    const AeadCryptingKeyRegistry& registry = GetAeadCryptingKeyRegistry();
    return registry.CreateRandomKeyData(key_label);
  } else if (key_label == "x25519-aes-256-gcm") {
    const HybridCryptingKeyRegistry& registry = GetHybridCryptingKeyRegistry();
    return registry.CreateRandomPrivateKeyData(key_label);
  } else if (key_label == "hmac-sha256-halfdigest") {
    const MacingKeyRegistry& registry = GetMacingKeyRegistry();
    return registry.CreateRandomKeyData(key_label);
  } else if (key_label == "p256-ecdsa") {
    const SigningKeyRegistry& registry = GetSigningKeyRegistry();
    return registry.CreateRandomPrivateKeyData(key_label);
  } else {
    return InvalidArgumentError(
        StrCat("Invalid key_label[", key_label,
               "] specified. Can't generated KeyData from key_label."));
  }
}

}  // namespace

const std::vector<std::shared_ptr<KeyHandle>>&
AdvancedKeysetManager::KeyHandles() {
  return keyset_handle_->key_handles();
}

StatusOr<std::shared_ptr<KeyHandle>> AdvancedKeysetManager::CreateNewKey(
    const absl::string_view key_label, const absl::string_view key_prefix) {
  Key key;
  auto status_or_key_data = KeyDataFromKeyLabel(key_label);
  if (!status_or_key_data.ok()) {
    return status_or_key_data.status();
  }
  *key.mutable_data() = status_or_key_data.ValueOrDie();
  *key.mutable_metadata()->mutable_prefix() = std::string(key_prefix);
  key.mutable_metadata()->set_status(CURRENT);
  key.mutable_metadata()->mutable_type()->set_google_key_type_label(
      key_label.data(), key_label.size());

  auto key_handle = std::make_shared<KeyHandle>(std::make_shared<Key>(key));
  keyset_handle_->key_handles_.push_back(key_handle);

  return key_handle;
}

Status AdvancedKeysetManager::SetKeyStatus(
    const std::shared_ptr<KeyHandle>& key_handle, KeyStatus key_status) {
  if (key_status == UNKNOWN_STATE) {
    return NotFoundError("key_status is UNKNOWN_STATE");
  }

  KeyMetadata* key_metadata = KeyUtil::GetKeyMetadata(key_handle);
  key_metadata->set_status(key_status);

  return OkStatus();
}

Status AdvancedKeysetManager::AddKey(
    const std::shared_ptr<KeyHandle>& key_handle) {
  keyset_handle_->key_handles_.push_back(key_handle);
  return OkStatus();
}

Status AdvancedKeysetManager::RemoveKey(
    const std::shared_ptr<KeyHandle>& key_handle) {
  bool found_key = false;
  int key_index = 0;
  for (const auto& item : keyset_handle_->key_handles_) {
    if (key_handle == item) {
      keyset_handle_->key_handles_.erase(keyset_handle_->key_handles_.begin() +
                                         key_index);
      found_key = true;
      break;
    }
    ++key_index;
  }

  if (!found_key) {
    return NotFoundError("couldn't find KeyHandle");
  }

  return OkStatus();
}

Status AdvancedKeysetManager::PromoteToPrimary(
    const std::shared_ptr<KeyHandle>& key_handle) {
  const std::vector<std::shared_ptr<KeyHandle>>& key_handles =
      keyset_handle_->key_handles();

  for (const auto& item : key_handles) {
    if (key_handle == item) {
      Status set_primary_key_status = keyset_handle_->SetPrimaryKey(key_handle);
      if (set_primary_key_status.ok()) {
        return OkStatus();
      }
      break;
    }
  }

  return NotFoundError("couldn't find KeyHandle");
}

}  // namespace crunchy
