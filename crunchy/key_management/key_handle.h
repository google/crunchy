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

#ifndef CRUNCHY_KEY_MANAGEMENT_KEY_HANDLE_H_
#define CRUNCHY_KEY_MANAGEMENT_KEY_HANDLE_H_

#include <memory>
#include <utility>

#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

// A KeyHandle is a view on top of a Key proto. This should be used as the
// primary API to read/access Keys.
class KeyHandle {
 public:
  explicit KeyHandle(std::shared_ptr<Key> key) : key_(std::move(key)) {}
  virtual ~KeyHandle() = default;

  StatusOr<std::shared_ptr<KeyHandle>> CloneAsPublicOnly() {
    auto cloned_key_handle = std::make_shared<Key>(*key_);
    if (cloned_key_handle->mutable_data()->public_key().empty()) {
      return FailedPreconditionError(
          "Failed to Clone Key as public-only. Key does not contain public key "
          "data.");
    }
    if (cloned_key_handle->mutable_data()->private_key().empty()) {
      return FailedPreconditionError(
          "Failed to Clone Key. Key does not contain private key data. Maybe "
          "the keyset is already public-only?");
    }
    cloned_key_handle->mutable_data()->clear_private_key();
    return std::make_shared<KeyHandle>(cloned_key_handle);
  }

  virtual const KeyMetadata& metadata() const { return key_->metadata(); }

 private:
  std::shared_ptr<Key> key_;

  friend class AdvancedKeysetManager;
  friend class KeyUtil;
};

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_KEY_HANDLE_H_
