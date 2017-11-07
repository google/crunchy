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

#include <vector>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/keys/key_util.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_manager.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

TEST(Interoperability, Success) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey("aes-128-gcm");
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));

  const std::string keyset_handle_serialized =
      KeysetHandleAsString(keyset_handle).ValueOrDie();
  const std::shared_ptr<KeysetHandle> keyset_handle_unserialized =
      KeysetHandleFromString(keyset_handle_serialized).ValueOrDie();

  EXPECT_EQ(keyset_handle_unserialized->primary_key_id(),
            keyset_handle->primary_key_id());
  EXPECT_EQ(keyset_handle_unserialized->key_handles().size(), 1);
  EXPECT_EQ(keyset_handle->key_handles().size(), 1);
  const Key expected_key = KeyUtil::KeyHandleAsProto(
      keyset_handle_unserialized->key_handles().at(0));
  const Key actual_key =
      KeyUtil::KeyHandleAsProto(keyset_handle->key_handles().at(0));
  EXPECT_EQ(expected_key.SerializeAsString(), actual_key.SerializeAsString());
}

TEST(Interoperability, InvalidSerializedKeyset) {
  EXPECT_EQ(FailedPreconditionError("Malformed keyset std::string."),
            KeysetHandleFromString("invalid string"));
}

}  // namespace

}  // namespace crunchy
