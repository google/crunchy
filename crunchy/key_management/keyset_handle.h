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

#ifndef CRUNCHY_KEY_MANAGEMENT_KEYSET_HANDLE_H_
#define CRUNCHY_KEY_MANAGEMENT_KEYSET_HANDLE_H_

#include <stdint.h>
#include <sys/types.h>
#include <memory>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "crunchy/key_management/key_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

// A KeysetHandle is a view on top of a Keyset proto. This should be used as the
// primary API to read/access Keysets.
class KeysetHandle {
 public:
  KeysetHandle() : primary_key_(nullptr) {}
  virtual ~KeysetHandle() = default;

  StatusOr<std::shared_ptr<KeysetHandle>> CloneAsPublicOnly();

  // The source of our Keyset (e.g., HSM, memory) can give a hint as to what
  // operations are possible with the keyset.
  std::string source() const { return "memory"; }

  const std::vector<std::shared_ptr<KeyHandle>>& key_handles();

  std::shared_ptr<KeyHandle> PrimaryKey();

  int32_t primary_key_id();

 protected:
  Status SetPrimaryKey(const std::shared_ptr<KeyHandle>& primary_key);

 private:
  std::vector<std::shared_ptr<KeyHandle>> key_handles_;
  std::shared_ptr<KeyHandle> primary_key_;

  friend class AdvancedKeysetManager;
  friend class KeysetUtil;
};

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_KEYSET_HANDLE_H_
