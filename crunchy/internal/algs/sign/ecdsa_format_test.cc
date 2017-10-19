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

#include "crunchy/internal/algs/sign/ecdsa_format.h"

#include <stdint.h>

#include <gtest/gtest.h>
#include "crunchy/internal/common/status_matchers.h"

namespace crunchy {

namespace {

#define R_BYTES \
  0x15, 0xcc, 0xc2, 0xdc, 0x48, 0xde, 0xd5, 0x91, \
  0xdd, 0x79, 0xaf, 0x7b, 0x96, 0xb2, 0x98, 0x51, \
  0x78, 0xf6, 0x80, 0xd8, 0x88, 0xcd, 0x96, 0x99, \
  0xf5, 0x61, 0x55, 0xb8, 0x10, 0xe9, 0x19, 0x29

#define S_BYTES \
  0xad, 0x83, 0x4a, 0x83, 0x48, 0xd4, 0x18, 0xe2, \
  0x2e, 0xe3, 0x56, 0x20, 0x4d, 0x53, 0x60, 0x0f, \
  0x3b, 0xa4, 0x3a, 0x63, 0x25, 0x6b, 0xf8, 0x8e, \
  0xeb, 0x26, 0x4f, 0x05, 0xd2, 0xe3, 0xc9, 0x05

const uint8_t random_r[] = {R_BYTES};

const uint8_t random_s[] = {S_BYTES};

const uint8_t random_encoded[] = {
    0x30,             // SEQUENCE
    2 + 32 + 2 + 33,  // length of seq
    0x02,             // INTEGER
    32,               // length of int
    R_BYTES,          // r
    0x02,             // INTEGER
    33,               // length of int
    0x00,             // pad as otherwise S_BYTES's 0xad would set the sign bit
    S_BYTES,          // s
};

}  // namespace

TEST(EcdsaUtilTest, RawToSEC1) {
  auto result_or = p256_ecdsa_raw_signature_to_asn1(
      absl::string_view(reinterpret_cast<const char*>(random_r),
                        sizeof(random_r)),
      absl::string_view(reinterpret_cast<const char*>(random_s),
                        sizeof(random_s)));
  ASSERT_TRUE(result_or.ok());
  std::string result = result_or.ValueOrDie();

  std::string expected(reinterpret_cast<const char*>(random_encoded),
                  sizeof(random_encoded));
  EXPECT_EQ(result, expected);
}

TEST(EcdsaUtilTest, SEC1ToRaw) {
  std::string r;
  std::string s;
  CRUNCHY_ASSERT_OK(p256_ecdsa_asn1_signature_to_raw(
      absl::string_view(reinterpret_cast<const char*>(random_encoded),
                        sizeof(random_encoded)),
      &r, &s));

  std::string expected_r(reinterpret_cast<const char*>(random_r), sizeof(random_r));
  std::string expected_s(reinterpret_cast<const char*>(random_s), sizeof(random_s));
  EXPECT_EQ(r, expected_r);
  EXPECT_EQ(s, expected_s);
}

}  // namespace crunchy
