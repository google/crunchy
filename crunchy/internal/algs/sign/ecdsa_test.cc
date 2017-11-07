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

#include "crunchy/internal/algs/sign/ecdsa.h"

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/hash/hash_interface.h"
#include "crunchy/internal/algs/hash/sha256.h"
#include "crunchy/internal/algs/hash/sha384.h"
#include "crunchy/internal/algs/hash/sha512.h"
#include "crunchy/internal/algs/openssl/ec.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/algs/sign/ecdsa_format.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/mem.h>

namespace crunchy {

namespace {

struct Rfc4754TestVector {
  Curve curve;
  const Hasher& hash;
  std::string public_key;
  std::string private_key;
  std::string message;
  std::string signature_r;
  std::string signature_s;
};

class EcdsaRfc4754Test : public ::testing::TestWithParam<Rfc4754TestVector> {
 public:
  std::unique_ptr<SignerFactory> Factory() const {
    return MakeEcdsaFactory(this->GetParam().curve, this->GetParam().hash,
                            SignatureFormat::ASN1);
  }

  std::unique_ptr<SignerInterface> Signer(absl::string_view private_key) const {
    return Factory()->MakeSigner(private_key).ValueOrDie();
  }

  std::unique_ptr<VerifierInterface> Verifier(
      absl::string_view public_key) const {
    return Factory()->MakeVerifier(public_key).ValueOrDie();
  }

  static std::vector<Rfc4754TestVector> Vectors() {
    // From https://tools.ietf.org/html/rfc4754#section-8
    return {
        {
            Curve::P256,
            Sha256::Instance(),
            "2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E9706F"
            "C98"
            "BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D",
            "DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F",
            "abc",
            "CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C",
            "86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315",
        },
        {
            Curve::P384,
            Sha384::Instance(),
            "96281BF8DD5E0525CA049C048D345D3082968D10FEDF5C5ACA0C64E6465A97EA5C"
            "E10C9DFEC21797415710721F437922447688BA94708EB6E2E4D59F6AB6D7EDFF93"
            "01D249FE49C33096655F5D502FAD3D383B91C5E7EDAA2B714CC99D5743CA",
            "0BEB646634BA87735D77AE4809A0EBEA865535DE4C1E1DCB692E84708E81A5AF62"
            "E528C38B2A81B35309668D73524D9F",
            "abc",
            "FB017B914E29149432D8BAC29A514640B46F53DDAB2C69948084E2930F1C8F7E08"
            "E07C9C63F2D21A07DCB56A6AF56EB3",
            "B263A1305E057F984D38726A1B46874109F417BCA112674C528262A40A629AF1CB"
            "B9F516CE0FA7D2FF630863A00E8B9F",
        },
        {
            Curve::P521,
            Sha512::Instance(),
            "0151518F1AF0F563517EDD5485190DF95A4BF57B5CBA4CF2A9A3F6474725A35F7A"
            "FE0A6DDEB8BEDBCD6A197E592D40188901CECD650699C9B5E456AEA5ADD19052A8"
            "006F3B142EA1BFFF7E2837AD44C9E4FF6D2D34C73184BBAD90026DD5E6E85317D9"
            "DF45CAD7803C6C20035B2F3FF63AFF4E1BA64D1C077577DA3F4286C58F0AEAE64"
            "3",
            "0065FDA3409451DCAB0A0EAD45495112A3D813C17BFD34BDF8C1209D7DF5849120"
            "597779060A7FF9D704ADF78B570FFAD6F062E95C7E0C5D5481C5B153B48B375FA"
            "1",
            "abc",
            "0154FD3836AF92D0DCA57DD5341D3053988534FDE8318FC6AAAAB68E2E6F4339B1"
            "9F2F281A7E0B22C269D93CF8794A9278880ED7DBB8D9362CAEACEE54432055225"
            "1",
            "017705A7030290D1CEB605A9A1BB03FF9CDD521E87A696EC926C8C10C8362DF497"
            "5367101F67D1CF9BCCBF2F3D239534FA509E70AAC851AE01AAC68D62F86647266"
            "0",
        },
    };
  }
};

TEST_P(EcdsaRfc4754Test, VerifyVectorSignature) {
  auto verifier = Verifier(absl::HexStringToBytes(this->GetParam().public_key));

  auto status_or_sig = ecdsa_raw_signature_to_asn1(
      absl::HexStringToBytes(this->GetParam().signature_r),
      absl::HexStringToBytes(this->GetParam().signature_s));
  CRUNCHY_EXPECT_OK(status_or_sig);

  CRUNCHY_EXPECT_OK(
      verifier->Verify(this->GetParam().message, status_or_sig.ValueOrDie()));
}

TEST_P(EcdsaRfc4754Test, Roundtrip) {
  auto signer = Signer(absl::HexStringToBytes(this->GetParam().private_key));
  auto status_or_sig = signer->Sign(this->GetParam().message);
  CRUNCHY_EXPECT_OK(status_or_sig);

  auto verifier = Verifier(absl::HexStringToBytes(this->GetParam().public_key));
  CRUNCHY_EXPECT_OK(
      verifier->Verify(this->GetParam().message, status_or_sig.ValueOrDie()));
}

TEST_P(EcdsaRfc4754Test, BadPublicKey) {
  std::string public_key = absl::HexStringToBytes(this->GetParam().public_key);

  CRUNCHY_EXPECT_OK(Factory()->MakeVerifier(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(Factory()->MakeVerifier(public_key).ok());
  public_key[0] ^= 0x01;
}

INSTANTIATE_TEST_CASE_P(, EcdsaRfc4754Test,
                        ::testing::ValuesIn(EcdsaRfc4754Test::Vectors()));

struct Rfc7515TestVector {
  Curve curve;
  const Hasher& hash;
  std::string public_key;
  std::string private_key;
  std::string message;
  std::string signature;
};

class EcdsaRfc7515Test : public ::testing::TestWithParam<Rfc7515TestVector> {
 public:
  std::unique_ptr<SignerFactory> Factory() const {
    return MakeEcdsaFactory(this->GetParam().curve, this->GetParam().hash,
                            SignatureFormat::JWT);
  }

  std::unique_ptr<SignerInterface> Signer(absl::string_view private_key) const {
    return Factory()->MakeSigner(private_key).ValueOrDie();
  }

  std::unique_ptr<VerifierInterface> Verifier(
      absl::string_view public_key) const {
    return Factory()->MakeVerifier(public_key).ValueOrDie();
  }

  static std::string DecodeB64(absl::string_view encoded) {
    std::string decoded;
    CRUNCHY_CHECK(absl::WebSafeBase64Unescape(encoded, &decoded)) << encoded;
    return decoded;
  }

  static std::vector<Rfc7515TestVector> Vectors() {
    return {
        {
            // https://tools.ietf.org/html/rfc7515#appendix-A.3
            Curve::P256,
            Sha256::Instance(),
            absl::StrCat(
                DecodeB64("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
                DecodeB64("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")),
            DecodeB64("jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"),
            "eyJhbGciOiJFUzI1NiJ9"
            "."
            "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6"
            "Ly9leGFt"
            "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
            DecodeB64("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-"
                      "F4GawxaepmXFCgfTjDxw5djxLa8ISlSA"
                      "pmWQxfKTUJqPP3-Kg6NU1Q"),
        },
        {
            // https://tools.ietf.org/html/rfc7515#appendix-A.4
            Curve::P521,
            Sha512::Instance(),
            absl::StrCat(
                DecodeB64("AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EO"
                          "nYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk"),
                DecodeB64("ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-"
                          "x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2")),
            DecodeB64("AY5pb7A0UFiB3RELSD64fTLOSV_"
                      "jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE"
                      "15j2C"),
            "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA",
            DecodeB64("AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_"
                      "UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_"
                      "7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO"
                      "7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn"),
        },
    };
  }
};

TEST_P(EcdsaRfc7515Test, VerifyVectorSignature) {
  auto verifier = Verifier(this->GetParam().public_key);

  CRUNCHY_EXPECT_OK(
      verifier->Verify(this->GetParam().message, this->GetParam().signature));
}

TEST_P(EcdsaRfc7515Test, Roundtrip) {
  auto signer = Signer(this->GetParam().private_key);
  auto status_or_sig = signer->Sign(this->GetParam().message);
  CRUNCHY_EXPECT_OK(status_or_sig);

  auto verifier = Verifier(this->GetParam().public_key);
  CRUNCHY_EXPECT_OK(
      verifier->Verify(this->GetParam().message, status_or_sig.ValueOrDie()));
}

TEST_P(EcdsaRfc7515Test, BadPublicKey) {
  auto public_key = std::string(this->GetParam().public_key);

  CRUNCHY_EXPECT_OK(Factory()->MakeVerifier(public_key));

  public_key[0] ^= 0x01;
  EXPECT_FALSE(Factory()->MakeVerifier(public_key).ok());
  public_key[0] ^= 0x01;
}

INSTANTIATE_TEST_CASE_P(, EcdsaRfc7515Test,
                        ::testing::ValuesIn(EcdsaRfc7515Test::Vectors()));

}  // namespace

}  // namespace crunchy
