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

#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"

#include <memory>

#include <gtest/gtest.h>
#include "absl/strings/string_view.h"
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace crunchy {
namespace {

TEST(OpenSSLMakeUniqueTest, Asn1Object) {
  openssl_unique_ptr<ASN1_OBJECT> ptr = openssl_make_unique<ASN1_OBJECT>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Asn1String) {
  openssl_unique_ptr<ASN1_STRING> ptr = openssl_make_unique<ASN1_STRING>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, AuthorityKeyId) {
  openssl_unique_ptr<AUTHORITY_KEYID> ptr =
      openssl_make_unique<AUTHORITY_KEYID>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, BigNum) {
  openssl_unique_ptr<BIGNUM> ptr = openssl_make_unique<BIGNUM>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Bio) {
  openssl_unique_ptr<BIO> ptr = openssl_make_unique<BIO>(BIO_s_mem());
}
TEST(OpenSSLMakeUniqueTest, BnCtx) {
  openssl_unique_ptr<BN_CTX> ptr = openssl_make_unique<BN_CTX>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, BufMem) {
  openssl_unique_ptr<BUF_MEM> ptr = openssl_make_unique<BUF_MEM>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Conf) {
  openssl_unique_ptr<CONF> ptr = openssl_make_unique<CONF>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Dh) {
  openssl_unique_ptr<DH> ptr = openssl_make_unique<DH>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, DistPoint) {
  openssl_unique_ptr<DIST_POINT> ptr = openssl_make_unique<DIST_POINT>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Dsa) {
  openssl_unique_ptr<DSA> ptr = openssl_make_unique<DSA>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, DsaSig) {
  openssl_unique_ptr<DSA_SIG> ptr = openssl_make_unique<DSA_SIG>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EcdsaSig) {
  openssl_unique_ptr<ECDSA_SIG> ptr = openssl_make_unique<ECDSA_SIG>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EcGroup) {
  openssl_unique_ptr<EC_GROUP> ptr(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EcKey) {
  openssl_unique_ptr<EC_KEY> ptr = openssl_make_unique<EC_KEY>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EcPoint) {
  openssl_unique_ptr<EC_GROUP> curve(
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  openssl_unique_ptr<EC_POINT> ptr = openssl_make_unique<EC_POINT>(curve.get());
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EvpCipherCtx) {
  openssl_unique_ptr<EVP_CIPHER_CTX> ptr =
      openssl_make_unique<EVP_CIPHER_CTX>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EvpPkey) {
  openssl_unique_ptr<EVP_PKEY> ptr = openssl_make_unique<EVP_PKEY>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, EvpPkeyCtx) {
  openssl_unique_ptr<EC_KEY> key(
      EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  EXPECT_EQ(1, EC_KEY_generate_key(key.get()));
  openssl_unique_ptr<EVP_PKEY> pkey = openssl_make_unique<EVP_PKEY>();
  EVP_PKEY_set1_EC_KEY(pkey.get(), key.get());

  openssl_unique_ptr<EVP_PKEY_CTX> ptr =
      openssl_make_unique<EVP_PKEY_CTX>(pkey.get(), nullptr);
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Rsa) {
  openssl_unique_ptr<RSA> ptr = openssl_make_unique<RSA>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509) {
  openssl_unique_ptr<X509> ptr = openssl_make_unique<X509>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509Crl) {
  openssl_unique_ptr<X509_CRL> ptr =
      openssl_make_unique<X509_CRL>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509Extension) {
  openssl_unique_ptr<X509_EXTENSION> ptr =
      openssl_make_unique<X509_EXTENSION>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509NameEntry) {
  openssl_unique_ptr<X509_NAME_ENTRY> ptr =
      openssl_make_unique<X509_NAME_ENTRY>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509Name) {
  openssl_unique_ptr<X509_NAME> ptr = openssl_make_unique<X509_NAME>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509Req) {
  openssl_unique_ptr<X509_REQ> ptr = openssl_make_unique<X509_REQ>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509Revoked) {
  openssl_unique_ptr<X509_REVOKED> ptr = openssl_make_unique<X509_REVOKED>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509Store) {
  openssl_unique_ptr<X509_STORE> ptr = openssl_make_unique<X509_STORE>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, x509StoreCtx) {
  openssl_unique_ptr<X509_STORE_CTX> ptr =
      openssl_make_unique<X509_STORE_CTX>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, X509VerifyParam) {
  openssl_unique_ptr<X509_VERIFY_PARAM> ptr =
      openssl_make_unique<X509_VERIFY_PARAM>();
  EXPECT_NE(nullptr, ptr);
}
TEST(OpenSSLMakeUniqueTest, Char) {
  openssl_unique_ptr<BIGNUM> bignum = openssl_make_unique<BIGNUM>();
  openssl_unique_ptr<char> ptr(BN_bn2hex(bignum.get()));
  EXPECT_NE(nullptr, ptr);
  EXPECT_EQ("0", absl::string_view(ptr.get()));
}

}  // namespace
}  // namespace crunchy
