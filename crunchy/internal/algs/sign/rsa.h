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

#ifndef CRUNCHY_ALGS_SIGN_RSA_H_
#define CRUNCHY_ALGS_SIGN_RSA_H_

#include "crunchy/internal/algs/hash/hash_interface.h"
#include "crunchy/internal/algs/openssl/rsa.h"
#include "crunchy/internal/algs/sign/signer_interface.h"

namespace crunchy {

// The padding algorithm of RSA signer.
enum class PaddingAlgorithm {
  // RSAPKCS1-v1_5 signer is based on RFC 3447
  // (https://tools.ietf.org/html/rfc3447) and can be used with both
  // SignModulusBitLength::B2048 and SignModulusBitLength::B4096 RSA signatures.
  PKCS1,
  // RSASSA-PSS signer is based on RFC 3447
  // (https://tools.ietf.org/html/rfc3447) and can be used with both
  // SignModulusBitLength::B2048 and SignModulusBitLength::B4096 RSA signatures.
  // The
  // salt length used matches the length of the hash algorithm.
  PSS,
};

enum class SignModulusBitLength {
  B2048 = 2048,
  B4096 = 4096,
};

// Produces an RSA signer based on modulus size, padding algorithm, e (the
// public exponent in RSA), and hash_algorithm (sha256, sha384, or sha512). The
// serialized public and private key are DER encoded.
std::unique_ptr<SignerFactory> MakeRsaFactory(
    SignModulusBitLength modulus_length, PaddingAlgorithm alg, int e,
    const Hasher& hash);

// Same as MakeRsaFactory, but in this case, the input std::string has already been
// hashed with the provided hash_algorithm.
std::unique_ptr<SignerFactory> MakeRsaFactoryWithHashedInput(
    SignModulusBitLength modulus_length, PaddingAlgorithm alg, int e,
    const Hasher& hash);

// Produces an RSA PKCS1-v1_5 signer based on RFC 3447
// (https://tools.ietf.org/html/rfc3447). The signer supports 2048-bit RSA
// signatures with e=2^16+1 and SHA256. The serialized public and private key
// are DER encoded.
const SignerFactory& GetRsa2048PkcsFactory();

// Produces an RSASSA-PSS signer based on RFC 3447. Only supports a salt length
// of 32. (https://tools.ietf.org/html/rfc3447). The signer supports 2048-bit
// RSA signatures with e=2^16+1 and SHA256. The serialized public and private
// key are DER encoded.
const SignerFactory& GetRsa2048PssFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_RSA_H_
