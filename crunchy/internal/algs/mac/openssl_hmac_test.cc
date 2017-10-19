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

#include "crunchy/internal/algs/mac/openssl_hmac.h"

#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/mac/testdata/mac_test_vectors.pb.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/port/port.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

const size_t kTestVectorMaxMessageSize = 42;

using testing::HasSubstr;
using testing::crunchy_status::StatusIs;

std::vector<FactoryInfo<MacFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<MacFactory>>();
  factories->push_back(
      {"HmacSha256", GetHmacSha256Factory(),
       "crunchy/internal/algs/mac/testdata/hmac_sha256.proto.bin"});
  return factories;
}

using MacTest = FactoryParamTest<MacFactory, FactoryInfoVector>;
const MacFactory& factory() { return GetHmacSha256Factory(); }

// Sign/Verify using a random key.
TEST_P(MacTest, SignVerify) {
  std::string key = RandString(factory().GetKeyLength());
  auto status_or_mac = factory().Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> mac = std::move(status_or_mac.ValueOrDie());

  std::string message = "banana";
  auto status_or_signature = mac->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());
  CRUNCHY_EXPECT_OK(mac->Verify(message, signature));

  // Twiddle some bits
  signature[0] ^= 0x01;
  EXPECT_THAT(mac->Verify(message, signature),
              StatusIs(INVALID_ARGUMENT, HasSubstr("Mac did not verify")));
  signature[0] ^= 0x01;

  message[0] ^= 0x01;
  EXPECT_THAT(mac->Verify(message, signature),
              StatusIs(INVALID_ARGUMENT, HasSubstr("Mac did not verify")));

  // Short signature
  EXPECT_THAT(mac->Verify(message, signature.substr(1)),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr(absl::StrCat(
                           "Signature length was ", signature.length() - 1,
                           " expected ", signature.length()))));
}

// Make sure the New function returns the same MAC object everytime.
TEST_P(MacTest, DeterministicGen) {
  std::string key = RandString(factory().GetKeyLength());
  auto status_or_mac = factory().Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> mac = std::move(status_or_mac.ValueOrDie());

  std::string message = "banana";
  auto status_or_signature = mac->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  status_or_mac = factory().Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> verify_mac =
      std::move(status_or_mac.ValueOrDie());

  CRUNCHY_EXPECT_OK(verify_mac->Verify(message, signature));
}

// Different keys should give different MAC objects.
TEST_P(MacTest, DifferentSigner) {
  std::string key = RandString(factory().GetKeyLength());
  auto status_or_mac = factory().Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> mac = std::move(status_or_mac.ValueOrDie());

  std::string message = "banana";
  auto status_or_signature = mac->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  key = RandString(factory().GetKeyLength());
  status_or_mac = factory().Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> verify_mac =
      std::move(status_or_mac.ValueOrDie());

  EXPECT_THAT(verify_mac->Verify(message, signature),
              StatusIs(INVALID_ARGUMENT, HasSubstr("Mac did not verify")));
}

TEST_P(MacTest, BadKeyLength) {
  std::string key = RandString(factory().GetKeyLength() + 1);
  EXPECT_THAT(factory().Make(key).status(),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr(absl::StrCat(
                           "Key length was ", key.length(), " but length ",
                           factory().GetKeyLength(), " is required"))));
  key = RandString(factory().GetKeyLength() - 1);
  EXPECT_THAT(factory().Make(key).status(),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr(absl::StrCat(
                           "Key length was ", key.length(), " but length ",
                           factory().GetKeyLength(), " is required"))));
}

INSTANTIATE_TEST_CASE_P(, MacTest, ::testing::ValuesIn(MacTest::factories()),
                        MacTest::GetNameFromParam);

void VerifyRfcTestVector(absl::string_view key, absl::string_view message,
                         absl::string_view signature) {
  std::unique_ptr<MacFactory> factory =
      MakeHmacSha256FactoryForTest(key.size(), signature.size());

  auto status_or_mac = factory->Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> mac = std::move(status_or_mac.ValueOrDie());

  auto status_or_signature = mac->Sign(message);
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  EXPECT_EQ(absl::BytesToHexString(status_or_signature.ValueOrDie()),
            absl::BytesToHexString(signature));

  status_or_mac = factory->Make(key);
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> verify_mac =
      std::move(status_or_mac.ValueOrDie());

  CRUNCHY_EXPECT_OK(verify_mac->Verify(message, signature));
}

// RFC 4231
// https://www.ietf.org/rfc/rfc4231
TEST(OpensslHmacTest, TestVectors) {
  // Section 4.2. Test Case 1
  {
    std::string key = absl::HexStringToBytes(
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        "0b0b0b0b");
    std::string message = "Hi There";
    std::string signature = absl::HexStringToBytes(
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7");
    VerifyRfcTestVector(key, message, signature);
  }

  // Section 4.3. Test Case 2
  {
    std::string key = "Jefe";
    std::string message = "what do ya want for nothing?";
    std::string signature = absl::HexStringToBytes(
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843");
    VerifyRfcTestVector(key, message, signature);
  }

  // Section 4.4. Test Case 3
  {
    std::string key = absl::HexStringToBytes(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaa");
    std::string message = absl::HexStringToBytes(
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd"
        "dddd");
    std::string signature = absl::HexStringToBytes(
        "773ea91e36800e46854db8ebd09181a7"
        "2959098b3ef8c122d9635514ced565fe");
    VerifyRfcTestVector(key, message, signature);
  }

  // Section 4.5. Test Case 4
  {
    std::string key = absl::HexStringToBytes(
        "0102030405060708090a0b0c0d0e0f10"
        "111213141516171819");
    std::string message = absl::HexStringToBytes(
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcd");
    std::string signature = absl::HexStringToBytes(
        "82558a389a443c0ea4cc819899f2083a"
        "85f0faa3e578f8077a2e3ff46729665b");
    VerifyRfcTestVector(key, message, signature);
  }

  // Section 4.6. Test Case 5
  {
    std::string key = absl::HexStringToBytes(
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
        "0c0c0c0c");
    std::string message = "Test With Truncation";
    std::string signature =
        absl::HexStringToBytes("a3b6167473100ee06e0c796c2955552b");
    VerifyRfcTestVector(key, message, signature);
  }

  // Section 4.7. Test Case 6
  {
    std::string key = absl::HexStringToBytes(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa");
    std::string message = "Test Using Larger Than Block-Size Key - Hash Key First";
    std::string signature = absl::HexStringToBytes(
        "60e431591ee0b67f0d8a26aacbf5b77f"
        "8e0bc6213728c5140546040f0ee37f54");
    VerifyRfcTestVector(key, message, signature);
  }

  // Section 4.8. Test Case 7
  {
    std::string key = absl::HexStringToBytes(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa");
    std::string message =
        "This is a test using a larger than block-size key and a larger than "
        "block-size data. The key needs to be hashed before being used by the "
        "HMAC algorithm.";

    std::string signature = absl::HexStringToBytes(
        "9b09ffa71b942fcb27635fbcd5b0e944"
        "bfdc63644f0713938a7f51535c3a35e2");
    VerifyRfcTestVector(key, message, signature);
  }
}

void VerifyTestVector(const MacFactory& factory,
                      const MacTestVector& test_vector) {
  auto status_or_mac = factory.Make(test_vector.key());
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> mac = std::move(status_or_mac.ValueOrDie());

  auto status_or_signature = mac->Sign(test_vector.message());
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  EXPECT_EQ(absl::BytesToHexString(status_or_signature.ValueOrDie()),
            absl::BytesToHexString(test_vector.signature()));

  status_or_mac = factory.Make(test_vector.key());
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> verify_mac =
      std::move(status_or_mac.ValueOrDie());

  CRUNCHY_EXPECT_OK(
      verify_mac->Verify(test_vector.message(), test_vector.signature()));
}

TEST_P(MacTest, TestVectors) {
  if (test_data_path().empty()) {
    CRUNCHY_LOG(ERROR) << name() << " has an empty test_data_path, skipping";
    return;
  }
  auto test_vectors = GetTestVectors<MacTestVectors>();
  for (const auto& test_vector : test_vectors->test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

MacTestVector GenerateTestVector(const MacFactory& factory) {
  MacTestVector test_vector;
  test_vector.set_key(RandString(factory.GetKeyLength()));
  size_t message_size = BiasRandInt(kTestVectorMaxMessageSize);

  auto status_or_mac = factory.Make(test_vector.key());
  CRUNCHY_EXPECT_OK(status_or_mac.status());
  std::unique_ptr<MacInterface> mac = std::move(status_or_mac.ValueOrDie());
  EXPECT_NE(mac, nullptr);

  test_vector.set_message(RandString(message_size));

  auto status_or_signature = mac->Sign(test_vector.message());
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  test_vector.set_signature(status_or_signature.ValueOrDie());

  VerifyTestVector(factory, test_vector);
  return test_vector;
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
