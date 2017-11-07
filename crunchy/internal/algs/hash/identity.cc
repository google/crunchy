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

#include "crunchy/internal/algs/hash/identity.h"

namespace crunchy {

const IdentityHash& IdentityHash::Instance() {
  static const IdentityHash& instance = *new IdentityHash();
  return instance;
}

StatusOr<std::string> IdentityHash::Hash(absl::string_view input) const {
  return std::string(input);
}

}  // namespace crunchy
