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

#ifndef CRUNCHY_KEY_MANAGEMENT_INTERNAL_ADVANCED_KEYSET_MANAGER_H_
#define CRUNCHY_KEY_MANAGEMENT_INTERNAL_ADVANCED_KEYSET_MANAGER_H_

#include <memory>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "crunchy/internal/keyset/key_registry.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

// The AdvancedKeysetManager is an internal class for manipulating Keysets.
class AdvancedKeysetManager {
 public:
  explicit AdvancedKeysetManager(std::shared_ptr<KeysetHandle> keyset_handle)
      : keyset_handle_(std::move(keyset_handle)) {}
  virtual ~AdvancedKeysetManager() = default;

  // Return a vector of all KeysetHandles in this Keyset.
  const std::vector<std::shared_ptr<KeyHandle>>& KeyHandles();

  // Generate a new key using the default registry for key_label and the
  // specified key_prefix.
  StatusOr<std::shared_ptr<KeyHandle>> CreateNewKey(
      const absl::string_view key_label, const absl::string_view key_prefix);

  // Generate a new key using the specified registry and key_prefix.
  StatusOr<std::shared_ptr<KeyHandle>> CreateNewKey(
      const KeyRegistry& key_registry, const absl::string_view key_label,
      const absl::string_view key_prefix);

  // Add the key in key_handle to the keyset.
  Status AddKey(const std::shared_ptr<KeyHandle>& key_handle);

  // Update the status of the key at key_handle to key_status.
  Status SetKeyStatus(const std::shared_ptr<KeyHandle>& key_handle,
                      KeyStatus key_status);

  // Immediately remote the specificed key from the keyset.
  Status RemoveKey(const std::shared_ptr<KeyHandle>& key_handle);

  // Mark a specific key as primary.
  Status PromoteToPrimary(const std::shared_ptr<KeyHandle>& key_handle);

 private:
  std::shared_ptr<KeysetHandle> keyset_handle_;
};

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_INTERNAL_ADVANCED_KEYSET_MANAGER_H_
