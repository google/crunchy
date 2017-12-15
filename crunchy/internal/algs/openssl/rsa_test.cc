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

#include "crunchy/internal/algs/openssl/rsa.h"

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "crunchy/internal/common/status_matchers.h"

namespace crunchy {
namespace {

using testing::HasSubstr;
using testing::crunchy_status::StatusIs;

static constexpr char kRsaHexDer[] =
    "3082010a0282010100c513dce157d0f9206ac0ae39982d0322dc61b5a27f1c557d66c97a96"
    "9242f41f4c9201ca78c2fae28d84714c58ec4a36a6b28f82bf1666efea3f5b60816b396780"
    "b535248cbf5ccc7140e320a89e7f5bb6609db33837cf528dd40650acd808b7123817a1b1b9"
    "89834d43d2fa4db2647e279fff73437700b7cbcffd9d7f4cf2820f70f54958f1b836b1bc67"
    "bff7e5a05336d1efff0156981b90e566c34fe9a44f95a53624189cec3c80f97025c7c4b522"
    "850f1bf20857d1f9908850c68d47bbac2b6074ba5b620cf80096cedb1d16271c2dc7f58eb2"
    "27debe4b103f9cc2ecd5e6ed03c80f17b4ffc61e53efedc13fefb64c949c14f628c02d61ed"
    "2d45e2463c430203010001";
static constexpr char kSubjectPublicKeyInfoPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxRPc4VfQ+SBqwK45mC0D
ItxhtaJ/HFV9Zsl6lpJC9B9MkgHKeML64o2EcUxY7Eo2prKPgr8WZu/qP1tggWs5
Z4C1NSSMv1zMcUDjIKief1u2YJ2zODfPUo3UBlCs2Ai3EjgXobG5iYNNQ9L6TbJk
fief/3NDdwC3y8/9nX9M8oIPcPVJWPG4NrG8Z7/35aBTNtHv/wFWmBuQ5WbDT+mk
T5WlNiQYnOw8gPlwJcfEtSKFDxvyCFfR+ZCIUMaNR7usK2B0ultiDPgAls7bHRYn
HC3H9Y6yJ96+SxA/nMLs1ebtA8gPF7T/xh5T7+3BP++2TJScFPYowC1h7S1F4kY8
QwIDAQAB
-----END PUBLIC KEY-----
)";
static constexpr char kRsaPublicKeyPem[] =
    R"(-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxRPc4VfQ+SBqwK45mC0DItxhtaJ/HFV9Zsl6lpJC9B9MkgHKeML6
4o2EcUxY7Eo2prKPgr8WZu/qP1tggWs5Z4C1NSSMv1zMcUDjIKief1u2YJ2zODfP
Uo3UBlCs2Ai3EjgXobG5iYNNQ9L6TbJkfief/3NDdwC3y8/9nX9M8oIPcPVJWPG4
NrG8Z7/35aBTNtHv/wFWmBuQ5WbDT+mkT5WlNiQYnOw8gPlwJcfEtSKFDxvyCFfR
+ZCIUMaNR7usK2B0ultiDPgAls7bHRYnHC3H9Y6yJ96+SxA/nMLs1ebtA8gPF7T/
xh5T7+3BP++2TJScFPYowC1h7S1F4kY8QwIDAQAB
-----END RSA PUBLIC KEY-----
)";

/* kEcdsa constants are legitimate Der / Pem keys, but not RSA,
 * therefore will generate errors if they are used.
 *
 * Generated as
 * $ openssl ecparam -name prime256v1 -genkey -noout -out private.pem
 * $ openssl ec -in private.pem -outform DER -pubout -out public.der
 * $ openssl ec -in public.der -inform DER -pubin -out public.pem -outform PEM
 */
static constexpr char kEcdsaBase64Der[] =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJpsVNF63k0Sc0FjpLMegVm+"
    "yX29tcNtySEL+Pg2xqa7DmlEJFTH4ScYs5YZbfnRmzZZj71RluldSSiGTLYTgQ == ";
static constexpr char kEcdsaPem[] =
    R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETJpsVNF63k0Sc0FjpLMegVm+yX29
tcNtySEL+Pg2xqa7DmlEJFTH4ScYs5YZbfnRmzZZj71RluldSSiGTLYTgQ==
-----END PUBLIC KEY-----
)";

TEST(DeserializeDerPublicKeyAsSubjectPublicKeyInfoPemTest, RsaHexDer) {
  auto status_or_pem = DeserializeDerPublicKeyAsSubjectPublicKeyInfoPem(
      absl::HexStringToBytes(kRsaHexDer));
  CRUNCHY_EXPECT_OK(status_or_pem.status());
  std::string pem = std::move(status_or_pem.ValueOrDie());
  EXPECT_EQ(pem, kSubjectPublicKeyInfoPem);
}

TEST(DeserializeDerPublicKeyAsSubjectPublicKeyInfoPemTest, NonRsaDer) {
  std::string unbased64_ecdsa;
  EXPECT_TRUE(absl::Base64Unescape(kEcdsaBase64Der, &unbased64_ecdsa));
  EXPECT_THAT(DeserializeDerPublicKeyAsSubjectPublicKeyInfoPem(unbased64_ecdsa),
              StatusIs(INTERNAL, HasSubstr("RSA generate key error")));
}

TEST(DeserializeSubjectPublicKeyInfoPemAsDerPublicKeyTest, RsaPem) {
  auto status_or_der = DeserializeSubjectPublicKeyInfoPemAsDerPublicKey(
      kSubjectPublicKeyInfoPem);
  CRUNCHY_EXPECT_OK(status_or_der.status());
  std::string der = std::move(status_or_der.ValueOrDie());
  EXPECT_EQ(absl::BytesToHexString(der), kRsaHexDer);
}

TEST(DeserializeSubjectPublicKeyInfoPemAsDerPublicKeyTest, NonRsaPem) {
  EXPECT_THAT(DeserializeSubjectPublicKeyInfoPemAsDerPublicKey(kEcdsaPem),
              StatusIs(INTERNAL, HasSubstr("public key type")));
}

TEST(DeserializeDerPublicKeyAsRsaPublicKeyPemTest, RsaHexDer) {
  auto status_or_pem = DeserializeDerPublicKeyAsRsaPublicKeyPem(
      absl::HexStringToBytes(kRsaHexDer));
  CRUNCHY_EXPECT_OK(status_or_pem.status());
  std::string pem = std::move(status_or_pem.ValueOrDie());
  EXPECT_EQ(pem, kRsaPublicKeyPem);
}

TEST(DeserializeDerPublicKeyAsRsaPublicKeyPemTest, NonRsaDer) {
  std::string unbased64_ecdsa;
  EXPECT_TRUE(absl::Base64Unescape(kEcdsaBase64Der, &unbased64_ecdsa));
  EXPECT_THAT(DeserializeDerPublicKeyAsRsaPublicKeyPem(unbased64_ecdsa),
              StatusIs(INTERNAL, HasSubstr("RSA generate key error")));
}

TEST(DeserializeRsaPublicKeyPemAsDerPublicKeyTest, RsaPem) {
  auto status_or_der =
      DeserializeRsaPublicKeyPemAsDerPublicKey(kRsaPublicKeyPem);
  CRUNCHY_EXPECT_OK(status_or_der.status());
  std::string der = std::move(status_or_der.ValueOrDie());
  EXPECT_EQ(absl::BytesToHexString(der), kRsaHexDer);
}

TEST(DeserializeRsaPublicKeyPemAsDerPublicKeyTest, NonRsaPem) {
  EXPECT_THAT(DeserializeRsaPublicKeyPemAsDerPublicKey(kEcdsaPem),
              StatusIs(INTERNAL, HasSubstr("error converting PEM to RSA")));
}

}  // namespace
}  // namespace crunchy
