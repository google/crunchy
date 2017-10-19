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

#include "crunchy/internal/algs/hybrid/dem.h"

#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"

namespace crunchy {

namespace {

using testing::HasSubstr;
using testing::crunchy_status::StatusIs;

std::vector<FactoryInfo<DemFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<DemFactory>>();
  factories->push_back({"AES_128_GCM", GetAes128GcmDemFactory()});
  factories->push_back({"AES_256_GCM", GetAes256GcmDemFactory()});
  return factories;
}

using DemTest = FactoryParamTest<DemFactory, FactoryInfoVector>;

TEST_P(DemTest, EncryptDecryptTest) {
  std::string key = RandString(factory().GetKeyLength());
  auto status_or_dem = factory().MakeDem(key);
  CRUNCHY_EXPECT_OK(status_or_dem.status());
  std::unique_ptr<Dem> dem = std::move(status_or_dem.ValueOrDie());

  std::string plaintext = RandString(42);

  auto status_or_ciphertext = dem->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  auto status_or_decrypted = dem->Decrypt(ciphertext);
  CRUNCHY_EXPECT_OK(status_or_decrypted.status());
  std::string decrypted = std::move(status_or_decrypted.ValueOrDie());

  EXPECT_EQ(plaintext, decrypted);
}

TEST_P(DemTest, BadKeyLengthTest) {
  std::string key = RandString(factory().GetKeyLength() - 1);
  auto status_or_dem = factory().MakeDem(key);
  EXPECT_FALSE(status_or_dem.ok());
}

TEST_P(DemTest, SmallCiphertextTest) {
  std::string key = RandString(factory().GetKeyLength());
  auto status_or_dem = factory().MakeDem(key);
  CRUNCHY_EXPECT_OK(status_or_dem.status());
  std::unique_ptr<Dem> dem = std::move(status_or_dem.ValueOrDie());

  std::string plaintext;

  auto status_or_ciphertext = dem->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  auto status_or_decrypted = dem->Decrypt(ciphertext.substr(0, 1));
  EXPECT_THAT(status_or_decrypted.status(),
              StatusIs(FAILED_PRECONDITION,
                       HasSubstr("ciphertext is not large enough")));

  status_or_decrypted = dem->Decrypt(ciphertext.substr(1));
  EXPECT_FALSE(status_or_decrypted.ok());
}

TEST_P(DemTest, CorruptCiphertextTest) {
  std::string key = RandString(factory().GetKeyLength());
  auto status_or_dem = factory().MakeDem(key);
  CRUNCHY_EXPECT_OK(status_or_dem.status());
  std::unique_ptr<Dem> dem = std::move(status_or_dem.ValueOrDie());

  std::string plaintext;

  auto status_or_ciphertext = dem->Encrypt(plaintext);
  CRUNCHY_EXPECT_OK(status_or_ciphertext.status());
  std::string ciphertext = std::move(status_or_ciphertext.ValueOrDie());

  ciphertext[0] ^= 0x01;
  auto status_or_decrypted = dem->Decrypt(ciphertext);
  EXPECT_FALSE(status_or_decrypted.ok());
  ciphertext[0] ^= 0x01;

  ciphertext[ciphertext.length() - 1] ^= 0x01;
  status_or_decrypted = dem->Decrypt(ciphertext);
  EXPECT_FALSE(status_or_decrypted.ok());
  ciphertext[ciphertext.length() - 1] ^= 0x01;
}

INSTANTIATE_TEST_CASE_P(, DemTest, ::testing::ValuesIn(DemTest::factories()),
                        DemTest::GetNameFromParam);

}  // namespace

}  // namespace crunchy
