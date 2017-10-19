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

#include <stddef.h>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "crunchy/internal/algs/sign/ed25519.h"
#include "crunchy/internal/algs/sign/p256_ecdsa.h"
#include "crunchy/internal/algs/sign/signer_interface.h"
#include "crunchy/internal/algs/sign/signer_test.h"
#include "crunchy/internal/algs/sign/testdata/sign_test_vectors.pb.h"
#include "crunchy/internal/common/flags.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

const size_t kTestVectorMaxMessageSize = 42;

std::vector<FactoryInfo<SignerFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<SignerFactory>>();
  factories->push_back(
      {"P256EcdsaAsn1", GetP256EcdsaAsn1Factory(),
       "crunchy/internal/algs/sign/testdata/p256_ecdsa_asn1.proto.bin"});
  factories->push_back(
      {"P256EcdsaJwt", GetP256EcdsaJwtFactory(),
       "crunchy/internal/algs/sign/testdata/p256_ecdsa_jwt.proto.bin"});
  factories->push_back(
      {"Ed25519", GetEd25519Factory(),
       "crunchy/internal/algs/sign/testdata/ed25519.proto.bin"});
  return factories;
}

using SignerTest = FactoryParamTest<SignerFactory, FactoryInfoVector>;

const char kMessage[] = "banana";

TEST_P(SignerTest, SignVerify) { SignVerifyTest(factory()); }

TEST_P(SignerTest, WrongSigner) { WrongSignerTest(factory()); }

TEST_P(SignerTest, BadSignature) { BadSignatureTest(factory()); }

TEST_P(SignerTest, TestVectors) {
  EXPECT_FALSE(test_data_path().empty())
      << name() << " has an empty test_data_path";
  auto test_vectors = GetTestVectors<SignerTestVectors>();
  for (const auto& test_vector : test_vectors->test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, SignerTest,
                        ::testing::ValuesIn(SignerTest::factories()),
                        SignerTest::GetNameFromParam);

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
