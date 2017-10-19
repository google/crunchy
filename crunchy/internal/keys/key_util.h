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

#ifndef CRUNCHY_INTERNAL_KEYS_KEY_UTIL_H_
#define CRUNCHY_INTERNAL_KEYS_KEY_UTIL_H_

#include <memory>
#include <string>

#include "absl/memory/memory.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

class KeyUtil {
 public:
  static Key KeyHandleAsProto(const std::shared_ptr<KeyHandle>& key_handle) {
    return *key_handle->key_;
  }

  static std::shared_ptr<KeyHandle> KeyHandleFromProto(const Key& key) {
    auto key_handle = std::make_shared<KeyHandle>(std::make_shared<Key>(key));
    return key_handle;
  }

  static StatusOr<std::shared_ptr<KeyHandle>> MakeCopy(
      const std::shared_ptr<KeyHandle>& key_handle) {
    auto cloned_key = std::make_shared<Key>(*key_handle->key_);
    if (cloned_key->mutable_data()->public_key().empty() &&
        cloned_key->mutable_data()->private_key().empty()) {
      return FailedPreconditionError(
          "Failed to Clone Key. Key does hold key material.");
    }
    return std::make_shared<KeyHandle>(cloned_key);
  }

  static KeyMetadata* GetKeyMetadata(std::shared_ptr<KeyHandle> key_handle) {
    return key_handle->key_->mutable_metadata();
  }
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYS_KEY_UTIL_H_
