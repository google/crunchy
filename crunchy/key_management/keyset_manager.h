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

#ifndef CRUNCHY_KEY_MANAGEMENT_KEYSET_MANAGER_H_
#define CRUNCHY_KEY_MANAGEMENT_KEYSET_MANAGER_H_

#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_enums.pb.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

// The user-facing API for keyset management.
// Each method directly modifies the underlying keyset.
class KeysetManager {
 public:
  explicit KeysetManager(std::shared_ptr<KeysetHandle> keyset_handle)
      : keyset_handle_(CRUNCHY_CHECK_NOTNULL(keyset_handle)),
        advanced_keyset_manager_(::absl::make_unique<AdvancedKeysetManager>(
            std::move(keyset_handle))) {}

  // Return a vector of all KeysetHandles in this Keyset.
  const std::vector<std::shared_ptr<KeyHandle>>& KeyHandles() {
    return advanced_keyset_manager_->KeyHandles();
  }

  // Return the keyset's primary key.
  std::shared_ptr<KeyHandle> PrimaryKey() {
    return advanced_keyset_manager_->KeyHandles().at(
        keyset_handle_->primary_key_id());
  }

  // Create a new key in the keyset.
  StatusOr<std::shared_ptr<KeyHandle>> GenerateAndAddNewKey(
      absl::string_view type_name);
  StatusOr<std::shared_ptr<KeyHandle>> GenerateAndAddNewKey(
      absl::string_view type_name, absl::string_view prefix);

  // Add an already-existing key from a KeyHandle.
  Status AddNewKey(const std::shared_ptr<KeyHandle>& key_handle);

  // Increment the primary_key_id to the next key in the keyset.
  StatusOr<std::shared_ptr<KeyHandle>> PromoteNextToPrimary() {
    if (keyset_handle_->key_handles().empty()) {
      return FailedPreconditionError(
          "Keyset is empty. Can't promote next key to primary.");
    }

    if (keyset_handle_->primary_key_id() >= 0 &&
        static_cast<size_t>(keyset_handle_->primary_key_id()) ==
            (keyset_handle_->key_handles().size() - 1)) {
      return FailedPreconditionError(
          "Newest key is already the primary key. Can't promote next key to "
          "primary.");
    }

    int new_primary_key_id;
    if (keyset_handle_->primary_key_id() == -1) {
      new_primary_key_id = 0;
    } else {
      new_primary_key_id = keyset_handle_->primary_key_id() + 1;
    }

    const std::shared_ptr<KeyHandle> key_handle =
        keyset_handle_->key_handles().at(new_primary_key_id);
    const Status promote_status =
        advanced_keyset_manager_->PromoteToPrimary(key_handle);
    if (!promote_status.ok()) {
      return promote_status;
    }

    return key_handle;
  }

  Status PromoteToPrimary(const std::shared_ptr<KeyHandle>& key_handle) {
    return advanced_keyset_manager_->PromoteToPrimary(key_handle);
  }

  // Delete the oldest key in the keyset.
  StatusOr<std::shared_ptr<KeyHandle>> DeleteOldestKey() {
    if (keyset_handle_->key_handles().empty()) {
      return FailedPreconditionError(
          "Keyset is empty. Can't delete oldest key.");
    }

    const std::shared_ptr<KeyHandle> oldest_key =
        keyset_handle_->key_handles().at(0);
    if (keyset_handle_->PrimaryKey() == oldest_key) {
      return FailedPreconditionError(
          "Oldest key is primary key. Can't delete oldest key.");
    }

    Status remove_key_status = advanced_keyset_manager_->RemoveKey(oldest_key);
    if (!remove_key_status.ok()) {
      return remove_key_status;
    }

    return oldest_key;
  }

  // Remove all keys in the keyset with status=DELETED.
  StatusOr<std::vector<std::shared_ptr<KeyHandle>>> GarbageCollectKeys() {
    std::vector<std::shared_ptr<KeyHandle>> keys_to_delete;
    for (const std::shared_ptr<KeyHandle>& key_handle :
         keyset_handle_->key_handles()) {
      if (key_handle->metadata().status() == KeyStatus::DELETED) {
        if (key_handle == keyset_handle_->PrimaryKey()) {
          return FailedPreconditionError(
              "Primary key has DELETED status. Refusing to delete.");
        }
        keys_to_delete.push_back(key_handle);
      }
    }
    for (const auto& key_handle : keys_to_delete) {
      advanced_keyset_manager_->RemoveKey(key_handle);
    }
    return keys_to_delete;
  }

  // Update ApplicationSpecificMetadata in the keyset.
  Status SetKeysetApplicationSpecificMetadata(const ::google::protobuf::Message& message) {
    return UnimplementedError("");
  }
  Status SetKeyApplicationSpecificMetadata(
      const std::shared_ptr<KeyHandle>& key_handle,
      const ::google::protobuf::Message& message) {
    return UnimplementedError("");
  }

 private:
  std::shared_ptr<KeysetHandle> keyset_handle_;
  std::unique_ptr<AdvancedKeysetManager> advanced_keyset_manager_;
};

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_KEYSET_MANAGER_H_
