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

#ifndef CRUNCHY_ALGS_OPENSSL_OPENSSL_UNIQUE_PTR_H_
#define CRUNCHY_ALGS_OPENSSL_OPENSSL_UNIQUE_PTR_H_

#include <algorithm>

#include "crunchy/internal/port/port.h"
#include <openssl/base.h>

namespace crunchy {

namespace internal {

template <typename T>
struct Tag {
  using type = T;
};

ASN1_OBJECT* Make(Tag<ASN1_OBJECT>);

ASN1_STRING* Make(Tag<ASN1_STRING>);

AUTHORITY_KEYID* Make(Tag<AUTHORITY_KEYID>);

BASIC_CONSTRAINTS* Make(Tag<BASIC_CONSTRAINTS>);

BIGNUM* Make(Tag<BIGNUM>);

BIO* Make(Tag<BIO>, const BIO_METHOD* type);

BN_CTX* Make(Tag<BN_CTX>);

BUF_MEM* Make(Tag<BUF_MEM>);

CONF* Make(Tag<CONF>);

DH* Make(Tag<DH>);

DIST_POINT* Make(Tag<DIST_POINT>);

DSA* Make(Tag<DSA>);

DSA_SIG* Make(Tag<DSA_SIG>);

ECDSA_SIG* Make(Tag<ECDSA_SIG>);

EC_KEY* Make(Tag<EC_KEY>);

EC_POINT* Make(Tag<EC_POINT>, const EC_GROUP* group);

EVP_CIPHER_CTX* Make(Tag<EVP_CIPHER_CTX>);

EVP_PKEY* Make(Tag<EVP_PKEY>);

EVP_PKEY_CTX* Make(Tag<EVP_PKEY_CTX>, EVP_PKEY *pkey, ENGINE *e);

RSA* Make(Tag<RSA>);

X509* Make(Tag<X509>);

X509_CRL* Make(Tag<X509_CRL>);

X509_EXTENSION* Make(Tag<X509_EXTENSION>);

X509_NAME_ENTRY* Make(Tag<X509_NAME_ENTRY>);

X509_NAME* Make(Tag<X509_NAME>);

X509_REQ* Make(Tag<X509_REQ>);

X509_REVOKED* Make(Tag<X509_REVOKED>);

X509_STORE* Make(Tag<X509_STORE>);

X509_STORE_CTX* Make(Tag<X509_STORE_CTX>);

X509_VERIFY_PARAM* Make(Tag<X509_VERIFY_PARAM>);

}  // namespace internal

template <typename T>
using openssl_unique_ptr = bssl::UniquePtr<T>;
template <typename T, typename... A>
bssl::UniquePtr<T> openssl_make_unique(A&&... a) {
  T* ptr = internal::Make(internal::Tag<T>{}, std::forward<A>(a)...);
  CRUNCHY_CHECK(ptr);
  return bssl::UniquePtr<T>(ptr);
}

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_OPENSSL_OPENSSL_UNIQUE_PTR_H_
