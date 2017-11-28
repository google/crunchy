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

#include "crunchy/internal/algs/kdf/hkdf.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include <gtest/gtest.h>
#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "crunchy/internal/common/status_matchers.h"

namespace crunchy {
namespace {

struct HKDFTest {
  const char* ikm;
  const char* salt;
  const char* info;
  const char* prk;  // expected prk
  const char* okm;  // expected okm
};

// Test cases taken from
// https://tools.ietf.org/html/rfc5869#appendix-A.
static const HKDFTest kHKDF256TestHex[] = {
    // for sha-256
    {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",  // 22-byte ikm
        "000102030405060708090a0b0c",                    // 13-byte salt
        "f0f1f2f3f4f5f6f7f8f9",                          // 10-byte info
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3"
        "e5",  // 32-byte prk
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5"
        "bf34007208d5b887185865",  // 42-byte okm
    },
    {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"
        "1f2021222324"
        "25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243"
        "4445464748494a4b4c4d4e4f",  // 80 bytes
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e"
        "7f8081828384"
        "85868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3"
        "a4a5a6a7a8a9aaabacadaeaf",  // 80 bytes
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdce"
        "cfd0d1d2d3d4"
        "d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3"
        "f4f5f6f7f8f9fafbfcfdfeff",  // 80 bytes
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc2"
        "44",  // 32 bytes
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa9"
        "7c59045a99ca"
        "c7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c581"
        "79ec3e87c14c01d5c1f3434f1d87",  // 82 bytes
    },
    {
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",  // 22 bytes
        "", "",
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb"
        "04",  // 32 bytes
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d"
        "2d9d201395faa4b61a96c8",  // 42 bytes
    },
};

// Generated test data, [prk] and [okm] are taken from test results.
static const HKDFTest kHKDF512TestHex[] = {
    {
        "696e697469616c206b6579206d6174657269616c",  // "initial key material"
        "73616c74",                                  // "salt"
        "7365637572697479207265616c6d206e616d65",    // "security realm name"
        "75a4fad18daa3a1826c0eda5bc9450588605ed6add204802f9b33859ed452229b89a32"
        "24ef90c8bd233d5394bdbce5fdbb14447df5dbb70f3556c298fa2fed4a",
        "2ead73ae175ba89dee052fa38abb8dfdf0281a57a7e3cd7de50eb90b9d4761c6a5722e"
        "e890fda24655e8993915b8610b816de7f3ccb1e2da01727e7100f061ed",
    },
};

void testHkdf(Hkdf* hkdf, const std::string& info, const std::string& prk_expected,
              const std::string& okm_expected) {
  /* Testing on HkdfExtract requires prk_ visible to public */
  // EXPECT_EQ(hkdf->prk_, prk_expected);
  const size_t okm_len = okm_expected.length();
  auto okm = absl::make_unique<uint8_t[]>(okm_len);
  CRUNCHY_ASSERT_OK(hkdf->HkdfExpand(info, okm_len, okm.get()));
  std::string okm_s(reinterpret_cast<const char*>(okm.get()), okm_len);
  EXPECT_EQ(okm_s, okm_expected);
}

TEST(HkdfSha256Test, HexStrings) {
  for (size_t i = 0; i < ABSL_ARRAYSIZE(kHKDF256TestHex); i++) {
    const HKDFTest& test(kHKDF256TestHex[i]);
    const std::string ikm = absl::HexStringToBytes(test.ikm);
    const std::string salt = absl::HexStringToBytes(test.salt);
    const std::string info = absl::HexStringToBytes(test.info);
    const std::string prk_expected = absl::HexStringToBytes(test.prk);
    EXPECT_EQ(prk_expected.length(), 32);
    const std::string okm_expected = absl::HexStringToBytes(test.okm);

    auto status_or_hkdf = MakeHkdfSha256(ikm, salt);
    CRUNCHY_ASSERT_OK(status_or_hkdf.status());
    auto hkdf = std::move(status_or_hkdf.ValueOrDie());
    testHkdf(hkdf.get(), info, prk_expected, okm_expected);
  }
}

TEST(HkdfSha512Test, HexStrings) {
  for (size_t i = 0; i < ABSL_ARRAYSIZE(kHKDF512TestHex); i++) {
    const HKDFTest& test(kHKDF512TestHex[i]);
    const std::string ikm = absl::HexStringToBytes(test.ikm);
    const std::string salt = absl::HexStringToBytes(test.salt);
    const std::string info = absl::HexStringToBytes(test.info);
    const std::string prk_expected = absl::HexStringToBytes(test.prk);
    EXPECT_EQ(prk_expected.length(), 64);
    const std::string okm_expected = absl::HexStringToBytes(test.okm);

    auto status_or_hkdf = MakeHkdfSha512(ikm, salt);
    CRUNCHY_ASSERT_OK(status_or_hkdf.status());
    auto hkdf = std::move(status_or_hkdf.ValueOrDie());
    testHkdf(hkdf.get(), info, prk_expected, okm_expected);
  }
}
}  // namespace
}  // namespace crunchy
