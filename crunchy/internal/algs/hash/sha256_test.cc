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

#include "crunchy/internal/algs/hash/sha256.h"

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

void TestOneVector(absl::string_view message,
                   absl::string_view expected_digest) {
  auto status_or = Sha256Hash(message);
  CRUNCHY_EXPECT_OK(status_or);
  EXPECT_EQ(status_or.ValueOrDie(), absl::HexStringToBytes(expected_digest));
}

void TestTwoVectors(absl::string_view message1, absl::string_view message2,
                    absl::string_view expected_digest) {
  auto status_or = Sha256Hash(message1, message2);
  CRUNCHY_EXPECT_OK(status_or);
  EXPECT_EQ(status_or.ValueOrDie(), absl::HexStringToBytes(expected_digest));
}

TEST(Sha256Test, TestVectors) {
  // From: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
  TestOneVector(
      "abc",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
  TestOneVector(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
}

TEST(Sha256Test, TwoInputTestVectors) {
  TestTwoVectors(
      "ab", "c",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
  TestTwoVectors(
      "abcdbcdecdefdefgefghfghi", "ghijhijkijkljklmklmnlmnomnopnopq",
      "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
}

}  // namespace

}  // namespace crunchy
