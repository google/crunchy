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

#include "crunchy/internal/algs/sign/rsa.h"

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
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

std::vector<FactoryInfo<SignerFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<SignerFactory>>();
  factories->push_back(
      {"Rsa2048Pkcs", GetRsa2048PkcsFactory(),
       "crunchy/internal/algs/sign/testdata/rsa2048_pkcs.proto.bin"});
  factories->push_back(
      {"Rsa2048Pss", GetRsa2048PssFactory(),
       "crunchy/internal/algs/sign/testdata/rsa2048_pss.proto.bin"});
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

TEST(Rsa2048, TestVectors) {
  std::string public_key_hex =
      "3082010a0282010100dfe2f5df9fa7cd96116034b97782c3421e34fb106e4590940d5a76"
      "db8b1855aa138466a4e867c2e8ef9253edb3ad008519738f8249f91a3707e4fdfa153c7e"
      "628579d48365a5333f1a1503687f068ad087f8b7dc130846e328fc86ad521d24f35936fe"
      "1ea6bc603e90dcb0e6ee5d71bf16bcc8cbffeb44de202064601c1f56474d3874a58a92b9"
      "68908337a429578b42a090ef27bea4e162976e7b7fdb7f254166fe8797ed9749818ab45f"
      "22639d34f0e9ce70e491ddb2fe77f55ada369aac260cfc007961e1af5d621d33bfc62c29"
      "0a9ae0390b04eb0922955bc7f279e209a82e86a633975237930ae34f6afcbb286a5c114e"
      "e91ba7cca666728c0834828f510203010001";
  std::string private_key_hex =
      "308204a50201000282010100dfe2f5df9fa7cd96116034b97782c3421e34fb106e459094"
      "0d5a76db8b1855aa138466a4e867c2e8ef9253edb3ad008519738f8249f91a3707e4fdfa"
      "153c7e628579d48365a5333f1a1503687f068ad087f8b7dc130846e328fc86ad521d24f3"
      "5936fe1ea6bc603e90dcb0e6ee5d71bf16bcc8cbffeb44de202064601c1f56474d3874a5"
      "8a92b968908337a429578b42a090ef27bea4e162976e7b7fdb7f254166fe8797ed974981"
      "8ab45f22639d34f0e9ce70e491ddb2fe77f55ada369aac260cfc007961e1af5d621d33bf"
      "c62c290a9ae0390b04eb0922955bc7f279e209a82e86a633975237930ae34f6afcbb286a"
      "5c114ee91ba7cca666728c0834828f510203010001028201004b3cf273dc2b8023566386"
      "546d9d3c111425a9d9b3b51d092413aaadcce8b8a1173dff609bd982ded4e3cfe0a9e911"
      "aba909f4c84c23b2739beb908e626499f471f6a73c21048b5c415f9e6d97829353d0ddfc"
      "abb099af78d76545bd2943320fb5838d92af65ced237cc7286a8c42e5d913e901c3e3cca"
      "3ffb7be73f8533e2c22274b119c2257e0a845db76b2df95c554fad2926a708ca555d2e25"
      "4ec084c2308367a8b1b94c4e513aa542d57020721e2956e9252d6923b93606d32ff8b142"
      "dac10016b0561133aa40080c74b02e2f86668a3205d10656b0f9608ef102df8afe5c4351"
      "23db4cad73d7fbf412ffa3bf0acad754caef8c896bf40fc9e2eb4a9d2102818100f537ef"
      "7aa0abb5e57c12eecb357e8d04d8a9e3523d52bb18717019190139987ad437ca13e2dd1c"
      "0af595a309c488f9fe9ba61ae74eef4c6340b1386dfb85f05e636f737fdc507ab22c486e"
      "0bbf18102f28ba2cc0f8ce2f4d51c9e77584de6038296cbdb5992c0c929ed43c7ae5fb05"
      "8f746e011f2e82668f0c7ac413eaa8e14f02818100e9baec37cd2d67918ee72c917953e5"
      "fc8c741a045ea46de9b95758ac86e98d45b7c8bd08e693c7047925d4ccccf28abf665e6d"
      "483a4d840e80a26963423a12f516df21024ceb330c3f917d1dcbb7c3114f2d7b0a20cd11"
      "ba4bd3fd1c51e782c740b01dc8e40349c66d2d5763e91b7795e27fb172773dd7ff63b033"
      "f9fe5f1d5f02818100a8cc654c3b7797d1ad93f6cee93700e9ba1f4ffcd77bb090c5dd8d"
      "593a0fa497c0a7dab1cfb3b6cf10787def865b68034caf8dcb75f9a1d29cc0a1808be88a"
      "2adf35e402baeca75928c47f0414fa028203fe0c3a95ca90a31fcee5466f3d086d008efb"
      "141ba947ca520cf4c900b0c80614f6784d379dc9ed6480c9a29020ca5f0281810099fe30"
      "e23709a24211c017ea24e0f51766c69bd9a32d7cc94ff6cf92a434be825fab1f78fcca02"
      "86dcf6e2f4a85768b8e04e787bed05e36ad6afaaf5ddcd7b6e054aaf69df99db0147e4a8"
      "657832339074f5472a8e1fee7d2ab699fe0dac95ca87c1416e7963fd3881f82caac40bf7"
      "c745fad1c3d3f2681c78e6bfe807034dcb02818100b006599d954cffb18cfe4723a7eb23"
      "bab737879f3002d51d482d81c98cf53d71adc72ba959336f05b5c4523253aedcb7680459"
      "bba602b6e21998160b62946542beb437b5830057d24702f706b4836463d7f88e350d0b77"
      "3d2d6d9e7894ff77918b004f4be94f124e9b86a38300787536d840f26396ba8fd453b6d8"
      "178c26a11e";

  std::string message = "abc";
  SignerTestVector test_vector;
  test_vector.set_public_key(absl::HexStringToBytes(public_key_hex));
  test_vector.set_private_key(absl::HexStringToBytes(private_key_hex));
  test_vector.set_message(message);

  std::string pkcs_signature_hex =
      "aa6d2e728cbab185b823c440b511209fe1930e059e88ae73c8308f0cf83a70fa5c57e146"
      "fd037598193b74ae63b536beea81975ca87408759b98b915946e09e1cee398558420ef56"
      "ac87283abf7ef0b666002e9aeb19f1ca2a04ca9948412e36e98c85971060f01f408bc4a1"
      "c9a7f9147871cb0983d0154bb3a8d27eb57e1ac238d673f8cc173ebae2e5c071e73dae48"
      "c2ce1a8ea2aae8fe93f6d40bb42fbe4a54b7474d3013f70aa27e03d5cd2cf8c836304660"
      "485e4bbd3da76a622ce577558b4c010e595b13df2562ff9c3043dcc81fdb58db70b189e8"
      "e467abf66de343bf6a9c500e91536e7ec475aecac1a5d19b962ef400cb288010504f7989"
      "41639be9";
  test_vector.set_signature(absl::HexStringToBytes(pkcs_signature_hex));
  const auto& pkcs_factory = GetRsa2048PkcsFactory();
  VerifyTestVector(pkcs_factory, test_vector);

  std::string pss_signature_hex =
      "66f0f78e1f3256b3a9947d4fef98b7a5412d5388b713cec6d65304b03b44171d20b55f36"
      "3f377ae5793dff7593c803824966524705e1e7ccd83d97cbfca54ba8632c1d87eda22519"
      "704ecfa0205b6bf4f4bd2afae58ebc59a2a79dcd9fe1102af95762543fdb89230afd37c6"
      "f9bf5f42469467bac235288c4f1dcdd39bae9bdeb74229c591480b67e18f6c2b7b86cad7"
      "9d548eaefc6c7c00ea316827ba1268cdbd847e24dfeecb4368217195db3eb408b0aa2cde"
      "9db4a4c277ed1b2bd93758cfd27701891b279b897e93b038610e41e793a92aeaeddb2cfd"
      "0993bea73f02907cca28b7e2f309bca72247a724a69031475de7cd7fed53b6853a13f68b"
      "2dc0180f";
  test_vector.set_signature(absl::HexStringToBytes(pss_signature_hex));
  const auto& pss_factory = GetRsa2048PssFactory();
  VerifyTestVector(pss_factory, test_vector);
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
