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

#include "crunchy/key_management/keyset_handle.h"

#include <stdint.h>
#include <sys/types.h>
#include <memory>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

StatusOr<std::shared_ptr<KeysetHandle>> KeysetHandle::CloneAsPublicOnly() {
  if (key_handles_.empty()) {
    return FailedPreconditionError("Failed to Clone Keyset. Keyset is empty.");
  }
  auto cloned_keyset_handle = std::make_shared<KeysetHandle>();
  for (const auto& key_handle : key_handles_) {
    auto status_or_cloned_key = key_handle->CloneAsPublicOnly();
    if (!status_or_cloned_key.ok()) {
      return status_or_cloned_key.status();
    }
    auto cloned_key = status_or_cloned_key.ValueOrDie();
    cloned_keyset_handle->key_handles_.push_back(cloned_key);
    if (key_handle == primary_key_) {
      cloned_keyset_handle->SetPrimaryKey(cloned_key);
    }
  }
  return cloned_keyset_handle;
}

const std::vector<std::shared_ptr<KeyHandle>>& KeysetHandle::key_handles() {
  return key_handles_;
}

std::shared_ptr<KeyHandle> KeysetHandle::PrimaryKey() { return primary_key_; }

int32_t KeysetHandle::primary_key_id() {
  for (size_t i = 0; i < key_handles_.size(); i++) {
    if (key_handles_.at(i) == primary_key_) {
      return i;
    }
  }
  return -1;
}

Status KeysetHandle::SetPrimaryKey(
    const std::shared_ptr<KeyHandle>& primary_key) {
  for (const auto& key_handle : key_handles_) {
    if (key_handle == primary_key) {
      primary_key_ = primary_key;
      return OkStatus();
    }
  }
  return FailedPreconditionError(
      "primary_key does not identify a key in this keyset.");
}

}  // namespace crunchy
