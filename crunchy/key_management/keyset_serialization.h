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

#ifndef CRUNCHY_KEY_MANAGEMENT_INTEROPERABILITY_H_
#define CRUNCHY_KEY_MANAGEMENT_INTEROPERABILITY_H_

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

StatusOr<std::string> KeysetHandleAsString(
    const std::shared_ptr<KeysetHandle>& keyset_handle);

StatusOr<std::shared_ptr<KeysetHandle>> KeysetHandleFromString(
    absl::string_view keyset);

}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_INTEROPERABILITY_H_
