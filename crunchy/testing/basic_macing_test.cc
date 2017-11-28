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

#include <memory>
#include <string>
#include <utility>

#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "crunchy/crunchy_macer.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/key_management/algorithms.h"
#include "crunchy/key_management/crunchy_factory.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/key_management/keyset_manager.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

TEST(BasicMacingTest, SignVerify) {
  // Create the keyset.
  auto keyset_handle = std::make_shared<KeysetHandle>();
  auto keyset_manager = ::absl::make_unique<KeysetManager>(keyset_handle);

  auto status_or_key_handle =
      keyset_manager->GenerateAndAddNewKey(GetHmacSha256HalfDigest());
  CRUNCHY_EXPECT_OK(status_or_key_handle.status());
  auto key_handle = status_or_key_handle.ValueOrDie();
  CRUNCHY_EXPECT_OK(keyset_manager->PromoteToPrimary(key_handle));

  // Use the keyset.
  auto status_or_macer = MakeCrunchyMacer(keyset_handle);
  CRUNCHY_EXPECT_OK(status_or_macer.status());
  std::unique_ptr<CrunchyMacer> macer = std::move(status_or_macer.ValueOrDie());
  const std::string message = "banana";
  auto status_or_signature = macer->Sign(message);
  CRUNCHY_ASSERT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_ASSERT_OK(macer->Verify(message, signature));
}

}  // namespace

}  // namespace crunchy
