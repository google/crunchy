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

#ifndef CRUNCHY_ALGS_SIGN_P256_ECDSA_H_
#define CRUNCHY_ALGS_SIGN_P256_ECDSA_H_

#include "crunchy/internal/algs/sign/signer_interface.h"

namespace crunchy {

// Factories that produce public/private keypairs and signer/verifiers for
// P256-ECDSA from FIPS 186-3
// http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
//
// The public key is formatted as the 32-byte x coordinate followed by the
// 32-byte y coordinate, both big-endian.
// The private key is a 32-byte big-endian exponent.

// Signatures are in ASN.1 format:
// https://tools.ietf.org/html/rfc5480
const SignerFactory& GetP256EcdsaAsn1Factory();

// Signatures are JWT-formated, the concatentation of a pair of 32-byte
// integers. a.k.a. "ES256" https://tools.ietf.org/html/rfc7518#section-3.4
const SignerFactory& GetP256EcdsaJwtFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_SIGN_P256_ECDSA_H_
