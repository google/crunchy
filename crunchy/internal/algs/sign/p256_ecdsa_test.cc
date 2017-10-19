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

#include "crunchy/internal/algs/sign/p256_ecdsa.h"

#include <memory>
#include <string>
#include <utility>

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "crunchy/internal/algs/sign/ecdsa_format.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

const char kMessage[] = "banana";

TEST(Asn1P256EcdsaTest, BadPublicKey) {
  const auto& factory = GetP256EcdsaAsn1Factory();

  std::string public_key_hex =
      "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970"
      "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
  std::string public_key = absl::HexStringToBytes(public_key_hex);

  CRUNCHY_EXPECT_OK(factory.MakeVerifier(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(factory.MakeVerifier(public_key).ok());
  public_key[0] ^= 0x01;
}

// RFC 4754 section 8.1
// https://www.ietf.org/rfc/rfc4754
TEST(Asn1P256EcdsaTest, TestVectors) {
  const auto& factory = GetP256EcdsaAsn1Factory();

  std::string public_key_hex =
      "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970"
      "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
  std::string private_key_hex =
      "DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F";

  std::string message = "abc";
  std::string signature_r_hex =
      "CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C";
  std::string signature_s_hex =
      "86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315";

  auto status_or_signature =
      p256_ecdsa_raw_signature_to_asn1(absl::HexStringToBytes(signature_r_hex),
                                       absl::HexStringToBytes(signature_s_hex));
  CRUNCHY_EXPECT_OK(status_or_signature.status());
  std::string signature = std::move(status_or_signature.ValueOrDie());

  auto status_or_signer =
      factory.MakeSigner(absl::HexStringToBytes(private_key_hex));
  CRUNCHY_EXPECT_OK(status_or_signer.status());
  std::unique_ptr<SignerInterface> signer =
      std::move(status_or_signer.ValueOrDie());

  auto status_or_verifier =
      factory.MakeVerifier(absl::HexStringToBytes(public_key_hex));
  CRUNCHY_EXPECT_OK(status_or_verifier.status());
  std::unique_ptr<VerifierInterface> verifier =
      std::move(status_or_verifier.ValueOrDie());

  CRUNCHY_EXPECT_OK(verifier->Verify(message, signature));

  {
    auto status_or_signature = signer->Sign(message);
    CRUNCHY_EXPECT_OK(status_or_signature.status());
    std::string another_signature = std::move(status_or_signature.ValueOrDie());
    CRUNCHY_EXPECT_OK(verifier->Verify(message, another_signature));

    status_or_signature = signer->Sign(kMessage);
    CRUNCHY_EXPECT_OK(status_or_signature.status());
    signature = std::move(status_or_signature.ValueOrDie());
    CRUNCHY_EXPECT_OK(verifier->Verify(kMessage, signature));
  }
}

TEST(JwtP256EcdsaTest, TestVectors) {
  const auto& factory = GetP256EcdsaJwtFactory();

  {
    // RFC 4754 section 8.1
    // https://www.ietf.org/rfc/rfc4754
    std::string public_key_hex =
        "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970"
        "6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D";
    std::string private_key_hex =
        "DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F";

    std::string message = "abc";
    std::string signature_hex =
        "CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C"
        "86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315";

    std::string signature = absl::HexStringToBytes(signature_hex);

    auto status_or_signer =
        factory.MakeSigner(absl::HexStringToBytes(private_key_hex));
    CRUNCHY_EXPECT_OK(status_or_signer.status());
    std::unique_ptr<SignerInterface> signer =
        std::move(status_or_signer.ValueOrDie());

    auto status_or_verifier =
        factory.MakeVerifier(absl::HexStringToBytes(public_key_hex));
    CRUNCHY_EXPECT_OK(status_or_verifier.status());
    std::unique_ptr<VerifierInterface> verifier =
        std::move(status_or_verifier.ValueOrDie());

    CRUNCHY_EXPECT_OK(verifier->Verify(message, signature));

    auto status_or_signature = signer->Sign(message);
    CRUNCHY_EXPECT_OK(status_or_signature.status());
    std::string another_signature = std::move(status_or_signature.ValueOrDie());
    CRUNCHY_EXPECT_OK(verifier->Verify(message, another_signature));

    status_or_signature = signer->Sign(kMessage);
    CRUNCHY_EXPECT_OK(status_or_signature.status());
    signature = std::move(status_or_signature.ValueOrDie());
    CRUNCHY_EXPECT_OK(verifier->Verify(kMessage, signature));
  }

  {
    // RFC 7515 section A.3
    // https://tools.ietf.org/html/rfc7515#appendix-A.3
    std::string public_key_x_base64 = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    std::string public_key_y_base64 = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    std::string private_key_base64 = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

    std::string message =
        "eyJhbGciOiJFUzI1NiJ9"
        "."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    std::string signature_base64 =
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
        "pmWQxfKTUJqPP3-Kg6NU1Q";

    std::string public_key_x;
    ASSERT_TRUE(
        absl::WebSafeBase64Unescape(public_key_x_base64, &public_key_x));
    std::string public_key_y;
    ASSERT_TRUE(
        absl::WebSafeBase64Unescape(public_key_y_base64, &public_key_y));
    std::string private_key;
    ASSERT_TRUE(absl::WebSafeBase64Unescape(private_key_base64, &private_key));
    std::string signature;
    ASSERT_TRUE(absl::WebSafeBase64Unescape(signature_base64, &signature));

    auto status_or_signer = factory.MakeSigner(private_key);
    CRUNCHY_EXPECT_OK(status_or_signer.status());
    std::unique_ptr<SignerInterface> signer =
        std::move(status_or_signer.ValueOrDie());

    auto status_or_verifier =
        factory.MakeVerifier(absl::StrCat(public_key_x, public_key_y));
    CRUNCHY_EXPECT_OK(status_or_verifier.status());
    std::unique_ptr<VerifierInterface> verifier =
        std::move(status_or_verifier.ValueOrDie());

    CRUNCHY_EXPECT_OK(verifier->Verify(message, signature));

    auto status_or_signature = signer->Sign(message);
    CRUNCHY_EXPECT_OK(status_or_signature.status());
    std::string another_signature = std::move(status_or_signature.ValueOrDie());
    CRUNCHY_EXPECT_OK(verifier->Verify(message, another_signature));

    status_or_signature = signer->Sign(kMessage);
    CRUNCHY_EXPECT_OK(status_or_signature.status());
    signature = std::move(status_or_signature.ValueOrDie());
    CRUNCHY_EXPECT_OK(verifier->Verify(kMessage, signature));
  }
}

}  // namespace

}  // namespace crunchy
