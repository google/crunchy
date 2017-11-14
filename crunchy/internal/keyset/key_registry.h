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

#ifndef CRUNCHY_INTERNAL_KEYSET_REGISTRY_H_
#define CRUNCHY_INTERNAL_KEYSET_REGISTRY_H_

#include "absl/strings/string_view.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

// Base class for all key registries.
class KeyRegistry {
 public:
  KeyRegistry() = default;
  virtual ~KeyRegistry() = default;

  KeyRegistry(const KeyRegistry&) = delete;

  virtual bool contains(const absl::string_view key_label) const = 0;

  virtual StatusOr<KeyData> CreateKeyData(
      const absl::string_view key_label) const = 0;
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYSET_REGISTRY_H_
