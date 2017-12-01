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

#include "crunchy/util/status.h"

namespace crunchy {

// Forward-declare to avoid including internal headers.
class Key;
class KeyMetadata;

// A KeyHandle is a view on top of a Key proto. This should be used as the
// primary API to read/access Keys.
class KeyHandle {
 public:
  explicit KeyHandle(std::shared_ptr<Key> key) : key_(std::move(key)) {}
  ~KeyHandle() = default;

  StatusOr<std::shared_ptr<KeyHandle>> CloneAsPublicOnly() const;

  const KeyMetadata& metadata() const;

 private:
  std::shared_ptr<Key> key_;

  friend class AdvancedKeysetManager;
  friend class KeyUtil;
};

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_KEY_HANDLE_H_
