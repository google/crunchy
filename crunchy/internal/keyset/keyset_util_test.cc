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

#include "crunchy/internal/keyset/keyset_util.h"

#include <gtest/gtest.h>
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/key_management/internal/advanced_keyset_manager.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_enums.pb.h"
#include "crunchy/key_management/keyset_manager.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

std::shared_ptr<KeysetHandle> GetDefaultKeysetHandle() {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);
  auto status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey("aes-128-gcm");
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));
  return keyset_handle;
}

TEST(KeysetUtilTest, SimpleMakeCopySuccess) {
  auto keyset_handle = GetDefaultKeysetHandle();
  auto keyset_handle_copy = KeysetUtil::MakeCopy(keyset_handle).ValueOrDie();

  auto keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  auto keyset_copy = KeysetUtil::KeysetHandleAsProto(keyset_handle_copy);

  EXPECT_EQ(keyset.SerializeAsString(), keyset_copy.SerializeAsString());
}

TEST(KeysetUtilTest, SimpleMakeEmptyKeysetError) {
  auto keyset_handle = std::make_shared<KeysetHandle>();
  EXPECT_FALSE(KeysetUtil::MakeCopy(keyset_handle).ok());
}

}  //  namespace

}  //  namespace crunchy
