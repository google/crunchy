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

#include "crunchy/internal/algs/openssl/ec.h"

#include <utility>

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "crunchy/internal/common/status_matchers.h"
#include <openssl/nid.h>

namespace crunchy {

namespace {

const EC_GROUP* group() {
  static const EC_GROUP* group =
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  return group;
}

TEST(EcTest, DeserializeSerializePointTest) {
  std::string point_hex =
      "2442a5cc0ecd015fa3ca31dc8e2bbc70bf42d60cbca20085e0822cb04235e970"
      "6fc98bd7e50211a4a27102fa3549df79ebcb4bf246b80945cddfe7d509bbfd7d";
  auto status_or_point =
      DeserializePoint(group(), absl::HexStringToBytes(point_hex));
  CRUNCHY_EXPECT_OK(status_or_point.status());
  openssl_unique_ptr<EC_POINT> point = std::move(status_or_point.ValueOrDie());

  auto status_or_serialized = SerializePoint(group(), point.get());
  CRUNCHY_EXPECT_OK(status_or_serialized.status());
  std::string serialized = std::move(status_or_serialized.ValueOrDie());
  EXPECT_EQ(point_hex, absl::BytesToHexString(serialized));

  // Mangle the first point
  serialized[0] ^= 0x01;
  EXPECT_FALSE(DeserializePoint(group(), serialized).ok());
  serialized[0] ^= 0x01;

  // Mangle the second point
  serialized[serialized.length() - 1] ^= 0x01;
  EXPECT_FALSE(DeserializePoint(group(), serialized).ok());
  serialized[serialized.length() - 1] ^= 0x01;

  // Short point
  EXPECT_FALSE(DeserializePoint(group(), absl::ClippedSubstr(
                                             absl::string_view(serialized), 1))
                   .ok());
}

TEST(EcTest, DeserializeSerializePrivateKeyTest) {
  std::string private_key_hex =
      "dc51d3866a15bacde33d96f992fca99da7e6ef0934e7097559c27f1614c88a7f";
  auto status_or_private_key =
      DeserializePrivateKey(group(), absl::HexStringToBytes(private_key_hex));
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  openssl_unique_ptr<EC_KEY> private_key =
      std::move(status_or_private_key.ValueOrDie());

  auto status_or_serialized = SerializePrivateKey(group(), private_key.get());
  CRUNCHY_EXPECT_OK(status_or_serialized.status());
  std::string serialized = std::move(status_or_serialized.ValueOrDie());
  EXPECT_EQ(private_key_hex, absl::BytesToHexString(serialized));

  // Short private key
  EXPECT_FALSE(
      DeserializePrivateKey(
          group(), absl::ClippedSubstr(absl::string_view(serialized), 1))
          .ok());
}

}  // namespace

}  // namespace crunchy
