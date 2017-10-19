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

#include "crunchy/internal/algs/crypt/aes_gcm.h"

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/crypt/crypter_interface.h"
#include "crunchy/internal/algs/crypt/crypter_test.h"
#include "crunchy/internal/algs/crypt/testdata/crypter_test_vectors.pb.h"
#include "crunchy/internal/common/flags.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/internal/common/test_factory.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

namespace {

std::vector<FactoryInfo<CrypterFactory>>* FactoryInfoVector() {
  auto factories = new std::vector<FactoryInfo<CrypterFactory>>();
  factories->push_back(
      {"Aes128Gcm", GetAes128GcmFactory(),
       "crunchy/internal/algs/crypt/testdata/aes_128_gcm.proto.bin"});
  factories->push_back(
      {"Aes256Gcm", GetAes256GcmFactory(),
       "crunchy/internal/algs/crypt/testdata/aes_256_gcm.proto.bin"});
  return factories;
}

using CrypterTest = FactoryParamTest<CrypterFactory, FactoryInfoVector>;

TEST_P(CrypterTest, RandomEncryptDecryptTests) {
  RandomEncryptDecryptTest(factory());
}

TEST_P(CrypterTest, EncryptionFailureTests) {
  EncryptionFailureTest(factory());
}

TEST_P(CrypterTest, DecryptionFailureTests) {
  DecryptionFailureTest(factory());
}

TEST_P(CrypterTest, RandomEncryptDecryptStringTests) {
  RandomEncryptDecryptStringTest(factory());
}

TEST_P(CrypterTest, EncryptionFailureStringTests) {
  EncryptionFailureStringTest(factory());
}

TEST_P(CrypterTest, DecryptionFailureStringTests) {
  DecryptionFailureStringTest(factory());
}

TEST_P(CrypterTest, TestVectors) {
  if (test_data_path().empty()) {
    CRUNCHY_LOG(ERROR) << name() << " has an empty test_data_path, skipping";
    return;
  }
  auto test_vectors = GetTestVectors<CrypterInterfaceTestVectors>();
  for (const auto& test_vector : test_vectors->vector()) {
    VerifyTestVector(factory(), test_vector);
  }
}

INSTANTIATE_TEST_CASE_P(, CrypterTest,
                        ::testing::ValuesIn(CrypterTest::factories()),
                        CrypterTest::GetNameFromParam);

void VerifyGcmTestVector(const CrypterInterfaceTestVector& test_vector) {
  if (test_vector.key().length() == GetAes128GcmFactory().GetKeyLength()) {
    VerifyTestVector(GetAes128GcmFactory(), test_vector);
  } else if (test_vector.key().length() ==
             GetAes256GcmFactory().GetKeyLength()) {
    VerifyTestVector(GetAes256GcmFactory(), test_vector);
  } else {
    CRUNCHY_LOG(FATAL) << "test vector had key of length "
                       << test_vector.key().length() << " which is unsupported";
  }
}

// From:
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
TEST(AesGcm, GcmPaper) {
  CrypterInterfaceTestVector test_vector;

  test_vector.set_key(
      absl::HexStringToBytes("00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("000000000000000000000000"));
  test_vector.set_aad("");
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("58e2fccefa7e3061367f1d57a4e7455a"));
  VerifyGcmTestVector(test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("00000000000000000000000000000000"));
  test_vector.set_nonce(absl::HexStringToBytes("000000000000000000000000"));
  test_vector.set_aad("");
  test_vector.set_plaintext(
      absl::HexStringToBytes("00000000000000000000000000000000"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("0388dace60b6a392f328c2b971b2fe78"
                             "ab6e47d42cec13bdf53a67b21257bddf"));
  VerifyGcmTestVector(test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("feffe9928665731c6d6a8f9467308308"));
  test_vector.set_nonce(absl::HexStringToBytes("cafebabefacedbaddecaf888"));
  test_vector.set_aad("");
  test_vector.set_plaintext(
      absl::HexStringToBytes("d9313225f88406e5a55909c5aff5269a"
                             "86a7a9531534f7da2e4c303d8a318a72"
                             "1c3c0c95956809532fcf0e2449a6b525"
                             "b16aedf5aa0de657ba637b391aafd255"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("42831ec2217774244b7221b784d0d49c"
                             "e3aa212f2c02a4e035c17e2329aca12e"
                             "21d514b25466931c7d8f6a5aac84aa05"
                             "1ba30b396a0aac973d58e091473f5985"
                             "4d5c2af327cd64a62cf35abd2ba6fab4"));
  VerifyGcmTestVector(test_vector);

  test_vector.set_key(
      absl::HexStringToBytes("feffe9928665731c6d6a8f9467308308"));
  test_vector.set_nonce(absl::HexStringToBytes("cafebabefacedbaddecaf888"));
  test_vector.set_aad(
      absl::HexStringToBytes("feedfacedeadbeeffeedfacedeadbeef"
                             "abaddad2"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("d9313225f88406e5a55909c5aff5269a"
                             "86a7a9531534f7da2e4c303d8a318a72"
                             "1c3c0c95956809532fcf0e2449a6b525"
                             "b16aedf5aa0de657ba637b39"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("42831ec2217774244b7221b784d0d49c"
                             "e3aa212f2c02a4e035c17e2329aca12e"
                             "21d514b25466931c7d8f6a5aac84aa05"
                             "1ba30b396a0aac973d58e091"
                             "5bc94fbc3221a5db94fae95ae7121a47"));
  VerifyGcmTestVector(test_vector);
}

// From:
// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
TEST(AesGcm, OddSizes) {
  CrypterInterfaceTestVector test_vector;


  // 2.1.1 54-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("AD7A2BD03EAC835A6F620FDCB506B345"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E5222A"
                             "B2C2846512153524C0895E8108000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "313233340001"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("F09478A9B09007D06F46E9B6A1DA25DD"));
  VerifyGcmTestVector(test_vector);

  // 2.1.2 54-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("E3C08A8F06C6E3AD95A70557B23F7548"
                             "3CE33021A9C72B7025666204C69C0B72"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E5222A"
                             "B2C2846512153524C0895E8108000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "313233340001"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("2F0BC5AF409E06D609EA8B7D0FA5EA50"));
  VerifyGcmTestVector(test_vector);

  // 2.2.1 60-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("AD7A2BD03EAC835A6F620FDCB506B345"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E52E00"
                             "B2C2846512153524C0895E81"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A0002"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("701AFA1CC039C0D765128A665DAB6924"
                             "3899BF7318CCDC81C9931DA17FBE8EDD"
                             "7D17CB8B4C26FC81E3284F2B7FBA713D"
                             "4F8D55E7D3F06FD5A13C0C29B9D5B880"));
  VerifyGcmTestVector(test_vector);

  // 2.2.2 60-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("E3C08A8F06C6E3AD95A70557B23F7548"
                             "3CE33021A9C72B7025666204C69C0B72"));
  test_vector.set_nonce(absl::HexStringToBytes("12153524C0895E81B2C28465"));
  test_vector.set_aad(
      absl::HexStringToBytes("D609B1F056637A0D46DF998D88E52E00"
                             "B2C2846512153524C0895E81"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A0002"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("E2006EB42F5277022D9B19925BC419D7"
                             "A592666C925FE2EF718EB4E308EFEAA7"
                             "C5273B394118860A5BE2A97F56AB7836"
                             "5CA597CDBB3EDB8D1A1151EA0AF7B436"));
  VerifyGcmTestVector(test_vector);

  // 2.3.1 60-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("071B113B0CA743FECCCF3D051F737382"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54000"
                             "76D457ED08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A0003"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("0C017BC73B227DFCC9BAFA1C41ACC353"));
  VerifyGcmTestVector(test_vector);

  // 2.3.2 60-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("691D3EE909D7F54167FD1CA0B5D76908"
                             "1F2BDE1AEE655FDBAB80BD5295AE6BE7"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54000"
                             "76D457ED08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A0003"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("35217C774BBC31B63166BCF9D4ABED07"));
  VerifyGcmTestVector(test_vector);

  // 2.4.1 54-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("071B113B0CA743FECCCF3D051F737382"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54C2A"
                             "76D457ED"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F30313233340004"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("13B4C72B389DC5018E72A171DD85A5D3"
                             "752274D3A019FBCAED09A425CD9B2E1C"
                             "9B72EEE7C9DE7D52B3F3"
                             "D6A5284F4A6D3FE22A5D6C2B960494C3"));
  VerifyGcmTestVector(test_vector);

  // 2.4.2 54-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("691D3EE909D7F54167FD1CA0B5D76908"
                             "1F2BDE1AEE655FDBAB80BD5295AE6BE7"));
  test_vector.set_nonce(absl::HexStringToBytes("F0761E8DCD3D000176D457ED"));
  test_vector.set_aad(
      absl::HexStringToBytes("E20106D7CD0DF0761E8DCD3D88E54C2A"
                             "76D457ED"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F30313233340004"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("C1623F55730C93533097ADDAD2566496"
                             "6125352B43ADACBD61C5EF3AC90B5BEE"
                             "929CE4630EA79F6CE519"
                             "12AF39C2D1FDC2051F8B7B3C9D397EF2"));
  VerifyGcmTestVector(test_vector);

  // 2.5.1 65-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("013FE00B5F11BE7F866D0CBBC55A7A90"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52300"
                             "8932D6127CFDE9F9E33724C608000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "3132333435363738393A3B3C3D3E3F00"
                             "05"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("217867E50C2DAD74C28C3B50ABDF695A"));
  VerifyGcmTestVector(test_vector);

  // 2.5.2 65-byte auth
  test_vector.set_key(
      absl::HexStringToBytes("83C093B58DE7FFE1C0DA926AC43FB360"
                             "9AC1C80FEE1B624497EF942E2F79A823"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52300"
                             "8932D6127CFDE9F9E33724C608000F10"
                             "1112131415161718191A1B1C1D1E1F20"
                             "2122232425262728292A2B2C2D2E2F30"
                             "3132333435363738393A3B3C3D3E3F00"
                             "05"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("6EE160E8FAECA4B36C86B234920CA975"));
  VerifyGcmTestVector(test_vector);

  // 2.6.1 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("013FE00B5F11BE7F866D0CBBC55A7A90"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52F00"
                             "8932D6127CFDE9F9E33724C6"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B00"
                             "06"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("3A4DE6FA32191014DBB303D92EE3A9E8"
                             "A1B599C14D22FB080096E13811816A3C"
                             "9C9BCF7C1B9B96DA809204E29D0E2A76"
                             "42"
                             "BFD310A4837C816CCFA5AC23AB003988"));
  VerifyGcmTestVector(test_vector);

  // 2.6.2 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("83C093B58DE7FFE1C0DA926AC43FB360"
                             "9AC1C80FEE1B624497EF942E2F79A823"));
  test_vector.set_nonce(absl::HexStringToBytes("7CFDE9F9E33724C68932D612"));
  test_vector.set_aad(
      absl::HexStringToBytes("84C5D513D2AAF6E5BBD2727788E52F00"
                             "8932D6127CFDE9F9E33724C6"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B00"
                             "06"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("110222FF8050CBECE66A813AD09A73ED"
                             "7A9A089C106B959389168ED6E8698EA9"
                             "02EB1277DBEC2E68E473155A15A7DAEE"
                             "D4"
                             "A10F4E05139C23DF00B3AADC71F0596A"));
  VerifyGcmTestVector(test_vector);

  // 2.7.1 79-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("88EE087FD95DA9FBF6725AA9D757B0CD"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54100"
                             "2E58495C08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A3B3C3D3E3F404142434445464748"
                             "494A4B4C4D0007"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("07922B8EBCF10BB2297588CA4C614523"));
  VerifyGcmTestVector(test_vector);

  // 2.7.2 79-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("4C973DBC7364621674F8B5B89E5C1551"
                             "1FCED9216490FB1C1A2CAA0FFE0407E5"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54100"
                             "2E58495C08000F101112131415161718"
                             "191A1B1C1D1E1F202122232425262728"
                             "292A2B2C2D2E2F303132333435363738"
                             "393A3B3C3D3E3F404142434445464748"
                             "494A4B4C4D0007"));
  test_vector.set_plaintext("");
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("00BDA1B7E87608BCBF470F12157F4C07"));
  VerifyGcmTestVector(test_vector);

  // 2.8.1 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("88EE087FD95DA9FBF6725AA9D757B0CD"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54D00"
                             "2E58495C"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B3C"
                             "3D3E3F404142434445464748490008"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("C31F53D99E5687F7365119B832D2AAE7"
                             "0741D593F1F9E2AB3455779B078EB8FE"
                             "ACDFEC1F8E3E5277F8180B43361F6512"
                             "ADB16D2E38548A2C719DBA7228D840"
                             "88F8757ADB8AA788D8F65AD668BE70E7"));
  VerifyGcmTestVector(test_vector);

  // 2.8.2 61-byte crypt
  test_vector.set_key(
      absl::HexStringToBytes("4C973DBC7364621674F8B5B89E5C1551"
                             "1FCED9216490FB1C1A2CAA0FFE0407E5"));
  test_vector.set_nonce(absl::HexStringToBytes("7AE8E2CA4EC500012E58495C"));
  test_vector.set_aad(
      absl::HexStringToBytes("68F2E77696CE7AE8E2CA4EC588E54D00"
                             "2E58495C"));
  test_vector.set_plaintext(
      absl::HexStringToBytes("08000F101112131415161718191A1B1C"
                             "1D1E1F202122232425262728292A2B2C"
                             "2D2E2F303132333435363738393A3B3C"
                             "3D3E3F404142434445464748490008"));
  test_vector.set_ciphertext_and_tag(
      absl::HexStringToBytes("BA8AE31BC506486D6873E4FCE460E7DC"
                             "57591FF00611F31C3834FE1C04AD80B6"
                             "6803AFCF5B27E6333FA67C99DA47C2F0"
                             "CED68D531BD741A943CFF7A6713BD0"
                             "2611CD7DAA01D61C5C886DC1A8170107"));
  VerifyGcmTestVector(test_vector);
}

}  // namespace

}  // namespace crunchy

int main(int argc, char** argv) {
  crunchy::InitCrunchyTest(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
