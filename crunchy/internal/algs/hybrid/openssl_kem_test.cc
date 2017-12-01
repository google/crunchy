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

#include "crunchy/internal/algs/hybrid/openssl_kem.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/hybrid/testdata/hybrid_test_vectors.pb.h"
#include "crunchy/internal/algs/hybrid/x25519_kem.h"
#include "crunchy/internal/algs/kdf/hkdf.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

using testing::HasSubstr;
using testing::crunchy_status::StatusIs;

const size_t kKeyLength = 42;
const char kInfo[] = "info";

const size_t kTestVectorMaxInfoSize = 42;
const size_t kTestVectorMaxKeySize = 42;

std::vector<FactoryInfo<KemFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<KemFactory>>();
  factories->push_back(
      {"P256", GetP256KemFactory(),
       "crunchy/internal/algs/hybrid/testdata/p256.proto.bin"});
  factories->push_back(
      {"P521", GetP521KemFactory(),
       "crunchy/internal/algs/hybrid/testdata/p521.proto.bin"});
  factories->push_back(
      {"x25519", GetX25519KemFactory(),
       "crunchy/internal/algs/hybrid/testdata/x25519.proto.bin"});
  return factories;
}

using KemTest = FactoryParamTest<KemFactory, FactoryInfoVector>;

void DerivationTest(const KemFactory& factory, const KemPublicKey& public_key,
                    const KemPrivateKey& private_key, size_t key_length,
                    absl::string_view info) {
  std::string client_key;
  std::string public_token;
  CRUNCHY_EXPECT_OK(
      public_key.NewKeyAndToken(key_length, info, &client_key, &public_token));
  EXPECT_EQ(key_length, client_key.length());
  EXPECT_EQ(public_token.length(), factory.KemPublicTokenSerializedSize());

  auto status_or_key =
      private_key.DeriveKeyFromToken(public_token, key_length, info);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  std::string server_key = std::move(status_or_key.ValueOrDie());
  EXPECT_EQ(key_length, server_key.length());
  EXPECT_EQ(server_key, client_key);
}

void DerivationTest(const KemFactory& factory, const KemPublicKey& public_key,
                    const KemPrivateKey& private_key) {
  return DerivationTest(factory, public_key, private_key, kKeyLength, kInfo);
}

TEST_P(KemTest, DerivationTest) {
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));
  EXPECT_NE(public_key.get(), nullptr);
  EXPECT_NE(private_key.get(), nullptr);

  // Test that the factory can derive secrets using the public and private keys.
  DerivationTest(factory(), *public_key, *private_key);
  DerivationTest(factory(), *public_key, *private_key, 0, "banana");
  DerivationTest(factory(), *public_key, *private_key, 1024, "apples");
}

TEST_P(KemTest, SerializeDeserializeTest) {
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));
  EXPECT_NE(public_key.get(), nullptr);
  EXPECT_NE(private_key.get(), nullptr);

  // Serialize and deserialize the public key.
  std::string serialized_public_key = public_key->Serialize();
  EXPECT_EQ(serialized_public_key.length(),
            factory().KemPublicKeySerializedSize());
  auto status_or_deserialized_public_key =
      factory().DeserializeKemPublicKey(serialized_public_key);
  CRUNCHY_EXPECT_OK(status_or_deserialized_public_key.status());
  std::unique_ptr<KemPublicKey> deserialized_public_key =
      std::move(status_or_deserialized_public_key.ValueOrDie());

  // Serialize and deserialize the private key.
  std::string serialized_private_key = private_key->Serialize();
  EXPECT_EQ(serialized_private_key.length(),
            factory().KemPrivateKeySerializedSize());
  auto status_or_deserialized_private_key =
      factory().DeserializeKemPrivateKey(serialized_private_key);
  CRUNCHY_EXPECT_OK(status_or_deserialized_private_key.status());
  std::unique_ptr<KemPrivateKey> deserialized_private_key =
      std::move(status_or_deserialized_private_key.ValueOrDie());

  // Make sure all the public/private keypairs generate the same secrets.
  DerivationTest(factory(), *public_key, *private_key);
  DerivationTest(factory(), *deserialized_public_key, *private_key);
  DerivationTest(factory(), *public_key, *deserialized_private_key);
  DerivationTest(factory(), *deserialized_public_key,
                 *deserialized_private_key);
}

TEST_P(KemTest, DistinctInfoTest) {
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));
  EXPECT_NE(public_key.get(), nullptr);
  EXPECT_NE(private_key.get(), nullptr);

  std::string client_key;
  std::string public_token;
  CRUNCHY_EXPECT_OK(public_key->NewKeyAndToken(kKeyLength, "apple", &client_key,
                                               &public_token));
  EXPECT_EQ(kKeyLength, client_key.length());
  EXPECT_EQ(public_token.length(), factory().KemPublicTokenSerializedSize());

  // Test using the same info, should give the same key
  {
    auto status_or_key =
        private_key->DeriveKeyFromToken(public_token, kKeyLength, "apple");
    CRUNCHY_EXPECT_OK(status_or_key.status());
    std::string server_key = std::move(status_or_key.ValueOrDie());
    EXPECT_EQ(kKeyLength, server_key.length());
    EXPECT_EQ(server_key, client_key);
  }

  // Test using the different info, should give the different key
  {
    auto status_or_key =
        private_key->DeriveKeyFromToken(public_token, kKeyLength, "orange");
    CRUNCHY_EXPECT_OK(status_or_key.status());
    std::string server_key = std::move(status_or_key.ValueOrDie());
    EXPECT_EQ(kKeyLength, server_key.length());
    EXPECT_NE(server_key, client_key);
  }
}

TEST_P(KemTest, DeserializationFailureTest) {
  std::string empty_string;
  std::string oddly_sized_string(1023, 0xed);
  EXPECT_THAT(factory().DeserializeKemPublicKey(empty_string).status(),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr("Length of serialized public key [0] does not "
                                 "match expected size [")));
  EXPECT_THAT(factory().DeserializeKemPublicKey(oddly_sized_string).status(),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr("Length of serialized public key [1023] does "
                                 "not match expected size [")));
  EXPECT_THAT(factory().DeserializeKemPrivateKey(empty_string).status(),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr("Length of serialized private key [0] does "
                                 "not match expected size [")));
  EXPECT_THAT(factory().DeserializeKemPrivateKey(oddly_sized_string).status(),
              StatusIs(INVALID_ARGUMENT,
                       HasSubstr("Length of serialized private key [1023] does "
                                 "not match expected size [")));
}

TEST_P(KemTest, BadTokenFailureTest) {
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));

  std::string empty_string;
  std::string oddly_sized_string(1023, 0xed);
  EXPECT_THAT(
      private_key->DeriveKeyFromToken(empty_string, kKeyLength, kInfo).status(),
      StatusIs(INVALID_ARGUMENT, HasSubstr("does not match expected size")));
  EXPECT_THAT(
      private_key->DeriveKeyFromToken(empty_string, kKeyLength, kInfo).status(),
      StatusIs(INVALID_ARGUMENT, HasSubstr("does not match expected size")));
}

TEST_P(KemTest, NullInputsFailureTest) {
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  EXPECT_THAT(factory().NewKeypair(nullptr, &private_key),
              StatusIs(INVALID_ARGUMENT, HasSubstr("public_key is null")));
  EXPECT_THAT(factory().NewKeypair(&public_key, nullptr),
              StatusIs(INVALID_ARGUMENT, HasSubstr("private_key is null")));
  CRUNCHY_EXPECT_OK(factory().NewKeypair(&public_key, &private_key));

  std::string client_key;
  std::string public_token;
  CRUNCHY_EXPECT_OK(public_key->NewKeyAndToken(kKeyLength, kInfo, &client_key,
                                               &public_token));
  EXPECT_THAT(
      public_key->NewKeyAndToken(kKeyLength, kInfo, nullptr, &public_token),
      StatusIs(INVALID_ARGUMENT, HasSubstr("key is null")));
  EXPECT_THAT(
      public_key->NewKeyAndToken(kKeyLength, kInfo, &client_key, nullptr),
      StatusIs(INVALID_ARGUMENT, HasSubstr("token is null")));
}

void VerifyTestVector(const KemFactory& factory,
                      const KemTestVector& test_vector) {
  EXPECT_EQ(test_vector.public_key().length(),
            factory.KemPublicKeySerializedSize());
  CRUNCHY_EXPECT_OK(
      factory.DeserializeKemPublicKey(test_vector.public_key()).status());

  EXPECT_EQ(test_vector.private_key().length(),
            factory.KemPrivateKeySerializedSize());
  auto status_or_private_key =
      factory.DeserializeKemPrivateKey(test_vector.private_key());
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<KemPrivateKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  EXPECT_EQ(test_vector.token().length(),
            factory.KemPublicTokenSerializedSize());
  auto status_or_derived = private_key->DeriveKeyFromToken(
      test_vector.token(), test_vector.derived().length(), test_vector.info());
  CRUNCHY_EXPECT_OK(status_or_derived.status());
  std::string derived = std::move(status_or_derived.ValueOrDie());
  CRUNCHY_CHECK_EQ(derived, test_vector.derived());
}

TEST_P(KemTest, TestVectors) {
  if (test_data_path().empty()) {
    CRUNCHY_LOG(ERROR) << name() << " has an empty test_data_path, skipping";
    return;
  }
  auto test_vectors = GetTestVectors<KemTestVectors>();
  for (const auto& test_vector : test_vectors.test_vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, KemTest, ::testing::ValuesIn(KemTest::factories()),
                        KemTest::GetNameFromParam);

TEST(P256Test, BadPublicKey) {
  const KemFactory& factory = GetP256KemFactory();

  std::string public_key = absl::HexStringToBytes(
      "b120de4aa36492795346e8de6c2c8646ae06aaea279fa775b3ab0715f6ce51b0"
      "9f1b7eece20d7b5ed8ec685fa3f071d83727027092a8411385c34dde5708b2b6");

  CRUNCHY_EXPECT_OK(factory.DeserializeKemPublicKey(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(factory.DeserializeKemPublicKey(public_key).ok());
  public_key[0] ^= 0x01;
}

TEST(P521Test, BadPublicKey) {
  const KemFactory& factory = GetP521KemFactory();

  std::string public_key = absl::HexStringToBytes(
      "01EBB34DD75721ABF8ADC9DBED17889CBB9765D90A7C60F2CEF007BB0F2B26E14881FD"
      "4442E689D61CB2DD046EE30E3FFD20F9A45BBDF6413D583A2DBF59924FD35C"
      "00F6B632D194C0388E22D8437E558C552AE195ADFD153F92D74908351B2F8C4EDA94ED"
      "B0916D1B53C020B5EECAED1A5FC38A233E4830587BB2EE3489B3B42A5A86A4");

  CRUNCHY_EXPECT_OK(factory.DeserializeKemPublicKey(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(factory.DeserializeKemPublicKey(public_key).ok());
  public_key[0] ^= 0x01;
}

void DhTest(const KemFactory& kem_factory, HkdfFactory* hkdf_factory,
            const std::string& public_key_hex, const std::string& private_key_hex,
            const std::string& expected_dh_hex) {
  std::string public_token = absl::HexStringToBytes(public_key_hex);

  std::string serialized_private_key = absl::HexStringToBytes(private_key_hex);
  auto status_or_private_key =
      kem_factory.DeserializeKemPrivateKey(serialized_private_key);
  CRUNCHY_EXPECT_OK(status_or_private_key.status());
  std::unique_ptr<KemPrivateKey> private_key =
      std::move(status_or_private_key.ValueOrDie());

  auto status_or_key =
      private_key->DeriveKeyFromToken(public_token, kKeyLength, kInfo);
  CRUNCHY_EXPECT_OK(status_or_key.status());
  std::string key = std::move(status_or_key.ValueOrDie());

  // Feed the expected_dh_hex through the hkdf.
  std::string ecdh_result = absl::HexStringToBytes(expected_dh_hex);
  auto status_or_hkdf =
      hkdf_factory(absl::StrCat(public_token, ecdh_result), "");
  CRUNCHY_EXPECT_OK(status_or_hkdf.status());
  std::unique_ptr<Hkdf> hkdf = std::move(status_or_hkdf.ValueOrDie());
  StringBuffer buffer(kKeyLength);
  CRUNCHY_EXPECT_OK(hkdf->HkdfExpand(kInfo, kKeyLength, buffer.data()));
  EXPECT_EQ(absl::BytesToHexString(key),
            absl::BytesToHexString(buffer.as_string()));
}

// RFC 5114 section A.6.
// https://tools.ietf.org/html/rfc5114.html
TEST(P256Test, TestVectors) {
  const KemFactory& kem_factory = GetP256KemFactory();
  HkdfFactory* hkdf_factory = MakeHkdfSha256;

  {
    const std::string public_key_hex =
        "b120de4aa36492795346e8de6c2c8646ae06aaea279fa775b3ab0715f6ce51b0"
        "9f1b7eece20d7b5ed8ec685fa3f071d83727027092a8411385c34dde5708b2b6";
    const std::string private_key_hex =
        "814264145f2f56f2e96a8e337a1284993faf432a5abce59e867b7291d507a3af";
    const std::string ecdh_result =
        "dd0f5396219d1ea393310412d19a08f1f5811e9dc8ec8eea7f80d21c820c2788";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
  {
    const std::string public_key_hex =
        "2af502f3be8952f2c9b5a8d4160d09e97165be50bc42ae4a5e8d3b4ba83aeb15"
        "eb0faf4ca986c4d38681a0f9872d79d56795bd4bff6e6de3c0f5015ece5efd85";
    const std::string private_key_hex =
        "2ce1788ec197e096db95a200cc0ab26a19ce6bccad562b8eee1b593761cf7f41";
    const std::string ecdh_result =
        "dd0f5396219d1ea393310412d19a08f1f5811e9dc8ec8eea7f80d21c820c2788";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
}

// RFC 5114 section A.8.
// https://tools.ietf.org/html/rfc5114.html
TEST(P521Test, TestVectors) {
  const KemFactory& kem_factory = GetP521KemFactory();
  HkdfFactory* hkdf_factory = MakeHkdfSha512;

  {
    const std::string public_key_hex =
        "01EBB34DD75721ABF8ADC9DBED17889CBB9765D90A7C60F2CEF007BB0F2B26E14881FD"
        "4442E689D61CB2DD046EE30E3FFD20F9A45BBDF6413D583A2DBF59924FD35C"
        "00F6B632D194C0388E22D8437E558C552AE195ADFD153F92D74908351B2F8C4EDA94ED"
        "B0916D1B53C020B5EECAED1A5FC38A233E4830587BB2EE3489B3B42A5A86A4";
    const std::string private_key_hex =
        "00CEE3480D8645A17D249F2776D28BAE616952D1791FDB4B70F7C3378732AA1B229284"
        "48BCD1DC2496D435B01048066EBE4F72903C361B1A9DC1193DC2C9D0891B96";
    const std::string ecdh_result =
        "00CDEA89621CFA46B132F9E4CFE2261CDE2D4368EB5656634C7CC98C7A00CDE54ED186"
        "6A0DD3E6126C9D2F845DAFF82CEB1DA08F5D87521BB0EBECA77911169C20CC";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
  {
    const std::string public_key_hex =
        "010EBFAFC6E85E08D24BFFFCC1A4511DB0E634BEEB1B6DEC8C5939AE44766201AF6200"
        "430BA97C8AC6A0E9F08B33CE7E9FEEB5BA4EE5E0D81510C24295B8A08D0235"
        "00A4A6EC300DF9E257B0372B5E7ABFEF093436719A77887EBB0B18CF8099B9F4212B6E"
        "30A1419C18E029D36863CC9D448F4DBA4D2A0E60711BE572915FBD4FEF2695";
    const std::string private_key_hex =
        "0113F82DA825735E3D97276683B2B74277BAD27335EA71664AF2430CC4F33459B9669E"
        "E78B3FFB9B8683015D344DCBFEF6FB9AF4C6C470BE254516CD3C1A1FB47362";
    const std::string ecdh_result =
        "00CDEA89621CFA46B132F9E4CFE2261CDE2D4368EB5656634C7CC98C7A00CDE54ED186"
        "6A0DD3E6126C9D2F845DAFF82CEB1DA08F5D87521BB0EBECA77911169C20CC";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
}

// RFC 7748 section 6.1.
// https://tools.ietf.org/html/rfc7748.html
TEST(X25519Test, TestVectors) {
  const KemFactory& kem_factory = GetX25519KemFactory();
  HkdfFactory* hkdf_factory = MakeHkdfSha256;

  {
    const std::string public_key_hex =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const std::string private_key_hex =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const std::string ecdh_result =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
  {
    const std::string public_key_hex =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const std::string private_key_hex =
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const std::string ecdh_result =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
}

// RFC 7748 section 6.1 values where private keys are mangled.
// https://tools.ietf.org/html/rfc7748.html
// Private key format: 255th and the first 3 bits are 1, 254th bit is zero.
TEST(X25519Test, TestVectorsMangled) {
  const KemFactory& kem_factory = GetX25519KemFactory();
  HkdfFactory* hkdf_factory = MakeHkdfSha256;

  {
    const std::string public_key_hex =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const std::string private_key_hex =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92caa";
    const std::string ecdh_result =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
  {
    const std::string public_key_hex =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const std::string private_key_hex =
        "5fab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0ab";
    const std::string ecdh_result =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    DhTest(kem_factory, hkdf_factory, public_key_hex, private_key_hex,
           ecdh_result);
  }
}

// BoringSSL produces mangled keys to ensure the underlying implementations are
// deterministically broken if they do not fix the private key.
TEST(X25519Test, TestNewPrivateKeyIsMangled) {
  const KemFactory& kem_factory = GetX25519KemFactory();
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  auto status = kem_factory.NewKeypair(&public_key, &private_key);
  CRUNCHY_EXPECT_OK(status);
  std::string private_key_str = private_key->Serialize();
  EXPECT_EQ(7, private_key_str[0] & 7);
  EXPECT_EQ(128, private_key_str[31] & 192);
}

KemTestVector GenerateTestVector(const KemFactory& factory) {
  KemTestVector test_vector;
  std::unique_ptr<KemPublicKey> public_key;
  std::unique_ptr<KemPrivateKey> private_key;
  CRUNCHY_EXPECT_OK(factory.NewKeypair(&public_key, &private_key));
  test_vector.set_private_key(private_key->Serialize());
  test_vector.set_public_key(public_key->Serialize());
  test_vector.set_info(RandString(BiasRandInt(kTestVectorMaxInfoSize)));
  size_t key_size = BiasRandInt(kTestVectorMaxKeySize);
  CRUNCHY_EXPECT_OK(public_key->NewKeyAndToken(key_size, test_vector.info(),
                                               test_vector.mutable_derived(),
                                               test_vector.mutable_token()));
  VerifyTestVector(factory, test_vector);
  return test_vector;
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
