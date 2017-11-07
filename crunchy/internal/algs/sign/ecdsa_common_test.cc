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
#include "crunchy/internal/algs/hash/identity.h"
#include "crunchy/internal/algs/hash/sha256.h"
#include "crunchy/internal/algs/hash/sha384.h"
#include "crunchy/internal/algs/hash/sha512.h"
#include "crunchy/internal/algs/sign/ecdsa.h"
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
  static const SignerFactory& p384EcdsaAsn1Factory =
      *MakeEcdsaFactory(Curve::P384, Sha384::Instance(), SignatureFormat::ASN1)
           .release();
  static const SignerFactory& p521EcdsaAsn1Factory =
      *MakeEcdsaFactory(Curve::P521, Sha512::Instance(), SignatureFormat::ASN1)
           .release();
  static const SignerFactory& p384EcdsaJwtFactory =
      *MakeEcdsaFactory(Curve::P384, Sha384::Instance(), SignatureFormat::JWT)
           .release();
  static const SignerFactory& p521EcdsaJwtFactory =
      *MakeEcdsaFactory(Curve::P521, Sha512::Instance(), SignatureFormat::JWT)
           .release();
  static const SignerFactory& p256PredigestedEcdsaAsn1Factory =
      *MakeEcdsaFactory(Curve::P256, IdentityHash::Instance(),
                        SignatureFormat::ASN1)
           .release();
  static const SignerFactory& p384PredigestedEcdsaAsn1Factory =
      *MakeEcdsaFactory(Curve::P384, IdentityHash::Instance(),
                        SignatureFormat::ASN1)
           .release();
  static const SignerFactory& p521PredigestedEcdsaAsn1Factory =
      *MakeEcdsaFactory(Curve::P521, IdentityHash::Instance(),
                        SignatureFormat::ASN1)
           .release();

  auto factories = new std::vector<FactoryInfo<SignerFactory>>();
  factories->push_back(
      {"P256EcdsaAsn1", GetP256EcdsaAsn1Factory(),
       "crunchy/internal/algs/sign/testdata/p256_ecdsa_asn1.proto.bin"});
  factories->push_back(
      {"P384EcdsaAsn1", p384EcdsaAsn1Factory,
       "crunchy/internal/algs/sign/testdata/p384_ecdsa_asn1.proto.bin"});
  factories->push_back(
      {"P521EcdsaAsn1", p521EcdsaAsn1Factory,
       "crunchy/internal/algs/sign/testdata/p521_ecdsa_asn1.proto.bin"});
  factories->push_back(
      {"P256EcdsaJwt", GetP256EcdsaJwtFactory(),
       "crunchy/internal/algs/sign/testdata/p256_ecdsa_jwt.proto.bin"});
  factories->push_back(
      {"P384EcdsaJwt", p384EcdsaJwtFactory,
       "crunchy/internal/algs/sign/testdata/p384_ecdsa_jwt.proto.bin"});
  factories->push_back(
      {"P521EcdsaJwt", p521EcdsaJwtFactory,
       "crunchy/internal/algs/sign/testdata/p521_ecdsa_jwt.proto.bin"});
  factories->push_back({"P256PredigestedEcdsaAsn1",
                        p256PredigestedEcdsaAsn1Factory,
                        "crunchy/internal/algs/sign/testdata/"
                        "p256_predigested_ecdsa_asn1.proto.bin"});
  factories->push_back({"P384PredigestedEcdsaAsn1",
                        p384PredigestedEcdsaAsn1Factory,
                        "crunchy/internal/algs/sign/testdata/"
                        "p384_predigested_ecdsa_asn1.proto.bin"});
  factories->push_back({"P521PredigestedEcdsaAsn1",
                        p521PredigestedEcdsaAsn1Factory,
                        "crunchy/internal/algs/sign/testdata/"
                        "p521_predigested_ecdsa_asn1.proto.bin"});
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
