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

#include "absl/strings/str_cat.h"
#include <openssl/asn1.h>
#include <openssl/base.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/cipher.h>
#include <openssl/conf.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

namespace crunchy {

namespace internal {

ASN1_OBJECT* Make(Tag<ASN1_OBJECT>) { return ASN1_OBJECT_new(); }

ASN1_STRING* Make(Tag<ASN1_STRING>) { return ASN1_STRING_new(); }

AUTHORITY_KEYID* Make(Tag<AUTHORITY_KEYID>) { return AUTHORITY_KEYID_new(); }

BASIC_CONSTRAINTS* Make(Tag<BASIC_CONSTRAINTS>) {
  return BASIC_CONSTRAINTS_new();
}

BIGNUM* Make(Tag<BIGNUM>) { return BN_new(); }

BIO* Make(Tag<BIO>, const BIO_METHOD* type) { return BIO_new(type); }

BN_CTX* Make(Tag<BN_CTX>) { return BN_CTX_new(); }

BUF_MEM* Make(Tag<BUF_MEM>) { return BUF_MEM_new(); }

CONF* Make(Tag<CONF>) { return NCONF_new(nullptr); }

DH* Make(Tag<DH>) { return DH_new(); }

DIST_POINT* Make(Tag<DIST_POINT>) { return DIST_POINT_new(); }

DSA* Make(Tag<DSA>) { return DSA_new(); }

DSA_SIG* Make(Tag<DSA_SIG>) { return DSA_SIG_new(); }

ECDSA_SIG* Make(Tag<ECDSA_SIG>) { return ECDSA_SIG_new(); }

EC_KEY* Make(Tag<EC_KEY>) { return EC_KEY_new(); }

EC_POINT* Make(Tag<EC_POINT>, const EC_GROUP* group) {
  return EC_POINT_new(group);
}

EVP_CIPHER_CTX* Make(Tag<EVP_CIPHER_CTX>) { return EVP_CIPHER_CTX_new(); }

EVP_PKEY* Make(Tag<EVP_PKEY>) { return EVP_PKEY_new(); }

EVP_PKEY_CTX* Make(Tag<EVP_PKEY_CTX>, EVP_PKEY* pkey, ENGINE* e) {
  return EVP_PKEY_CTX_new(pkey, e);
}

RSA* Make(Tag<RSA>) { return RSA_new(); }

X509* Make(Tag<X509>) { return X509_new(); }

X509_CRL* Make(Tag<X509_CRL>) { return X509_CRL_new(); }

X509_EXTENSION* Make(Tag<X509_EXTENSION>) { return X509_EXTENSION_new(); }

X509_NAME_ENTRY* Make(Tag<X509_NAME_ENTRY>) { return X509_NAME_ENTRY_new(); }

X509_NAME* Make(Tag<X509_NAME>) { return X509_NAME_new(); }

X509_REQ* Make(Tag<X509_REQ>) { return X509_REQ_new(); }

X509_REVOKED* Make(Tag<X509_REVOKED>) { return X509_REVOKED_new(); }

X509_STORE* Make(Tag<X509_STORE>) { return X509_STORE_new(); }

X509_STORE_CTX* Make(Tag<X509_STORE_CTX>) { return X509_STORE_CTX_new(); }

X509_VERIFY_PARAM* Make(Tag<X509_VERIFY_PARAM>) {
  return X509_VERIFY_PARAM_new();
}

}  // namespace internal

}  // namespace crunchy
