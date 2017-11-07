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

#include "crunchy/key_management/keyset_serialization.h"

#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/key_management/internal/keyset.pb.h"

namespace crunchy {

StatusOr<std::string> KeysetHandleAsString(
    const std::shared_ptr<KeysetHandle>& keyset_handle) {
  Keyset keyset_proto = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return keyset_proto.SerializeAsString();
}

StatusOr<std::shared_ptr<KeysetHandle>> KeysetHandleFromString(
    absl::string_view keyset) {
  Keyset keyset_proto;
  if (!keyset_proto.ParseFromArray(keyset.data(), keyset.size())) {
    return FailedPreconditionError("Malformed keyset std::string.");
  }
  return KeysetUtil::KeysetHandleFromProto(keyset_proto);
}

}  // namespace crunchy
