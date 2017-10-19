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

#ifndef CRUNCHY_INTERNAL_KEYS_MACING_KEY_H_
#define CRUNCHY_INTERNAL_KEYS_MACING_KEY_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/mac/mac_interface.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

class MacingKey {
 public:
  virtual ~MacingKey() = default;

  virtual StatusOr<std::string> Sign(absl::string_view message) const = 0;
  virtual Status Verify(absl::string_view message,
                        absl::string_view signature) const = 0;
};

class MacingKeyFactory {
 public:
  virtual ~MacingKeyFactory() = default;

  virtual KeyData CreateRandomKeyData() const = 0;
  virtual StatusOr<std::unique_ptr<MacingKey>> MakeKey(
      const KeyData& key_data) const = 0;
};

std::unique_ptr<MacingKeyFactory> MakeFactory(const MacFactory& factory);

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYS_MACING_KEY_H_
