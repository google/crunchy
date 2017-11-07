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

#ifndef CRUNCHY_ALGS_HASH_IDENTITY_H_
#define CRUNCHY_ALGS_HASH_IDENTITY_H_

#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/hash/hash_interface.h"
#include "crunchy/util/status.h"

namespace crunchy {

class IdentityHash : public Hasher {
 public:
  static const IdentityHash& Instance();

  StatusOr<std::string> Hash(absl::string_view input) const override;
};

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HASH_IDENTITY_H_
