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

#include <memory>
#include <vector>

#include "absl/strings/string_view.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_enums.pb.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

// Forward-declare to avoid including internal headers.
class AdvancedKeysetManager;
class KeyType;

// The user-facing API for keyset management.
// Each method directly modifies the underlying keyset.
class KeysetManager {
 public:
  explicit KeysetManager(std::shared_ptr<KeysetHandle> keyset_handle);
  ~KeysetManager();

  // Return a vector of all KeysetHandles in this Keyset.
  const std::vector<std::shared_ptr<KeyHandle>>& KeyHandles() const;

  // Return the keyset's primary key.
  std::shared_ptr<KeyHandle> PrimaryKey();

  // Create a new key in the keyset.
  StatusOr<std::shared_ptr<KeyHandle>> GenerateAndAddNewKey(
      const KeyType& type);

  // Increment the primary_key_id to the next key in the keyset.
  StatusOr<std::shared_ptr<KeyHandle>> PromoteNextToPrimary();

  Status PromoteToPrimary(const std::shared_ptr<KeyHandle>& key_handle);

  // Delete the oldest key in the keyset.
  StatusOr<std::shared_ptr<KeyHandle>> DeleteOldestKey();

  // Remove all keys in the keyset with status=DELETED.
  StatusOr<std::vector<std::shared_ptr<KeyHandle>>> GarbageCollectKeys();

 private:
  std::shared_ptr<KeysetHandle> keyset_handle_;
  std::unique_ptr<AdvancedKeysetManager> advanced_keyset_manager_;
};

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_KEYSET_MANAGER_H_
