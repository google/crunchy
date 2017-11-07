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

#ifndef CRUNCHY_INTERNAL_KEYSET_KEYSET_UTIL_H_
#define CRUNCHY_INTERNAL_KEYSET_KEYSET_UTIL_H_

#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

class KeysetUtil {
 public:
  static Keyset KeysetHandleAsProto(
      const std::shared_ptr<KeysetHandle>& keyset_handle) {
    Keyset keyset;
    keyset.set_primary_key_id(keyset_handle->primary_key_id());
    for (const auto& key_handle : keyset_handle->key_handles_) {
      *keyset.add_key() = KeyUtil::KeyHandleAsProto(key_handle);
    }
    return keyset;
  }

  static StatusOr<std::shared_ptr<KeysetHandle>> KeysetHandleFromProto(
      const Keyset& keyset) {
    auto keyset_handle = std::make_shared<KeysetHandle>();
    for (int i = 0; i < keyset.key().size(); i++) {
      const auto& key = keyset.key(i);
      const auto& key_handle = KeyUtil::KeyHandleFromProto(key);
      keyset_handle->key_handles_.push_back(key_handle);
      if (i == keyset.primary_key_id()) {
        Status status = keyset_handle->SetPrimaryKey(key_handle);
        if (!status.ok()) {
          return status;
        }
      }
    }
    return keyset_handle;
  }

  static StatusOr<std::shared_ptr<KeysetHandle>> MakeCopy(
      const std::shared_ptr<KeysetHandle>& keyset_handle) {
    if (keyset_handle->key_handles().empty()) {
      return FailedPreconditionError("Failed to Copy Keyset. Keyset is empty.");
    }
    auto cloned_keyset_handle = std::make_shared<KeysetHandle>();
    for (const auto& key_handle : keyset_handle->key_handles()) {
      auto status_or_cloned_key = KeyUtil::MakeCopy(key_handle);
      if (!status_or_cloned_key.ok()) {
        return status_or_cloned_key.status();
      }
      const auto& cloned_key = status_or_cloned_key.ValueOrDie();
      cloned_keyset_handle->key_handles_.push_back(cloned_key);
      if (key_handle == keyset_handle->PrimaryKey()) {
        Status status = cloned_keyset_handle->SetPrimaryKey(cloned_key);
        if (!status.ok()) {
          return status;
        }
      }
    }
    return cloned_keyset_handle;
  }
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYSET_KEYSET_UTIL_H_
