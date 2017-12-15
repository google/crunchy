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

#ifndef CRUNCHY_ALGS_OPENSSL_RSA_H_
#define CRUNCHY_ALGS_OPENSSL_RSA_H_

#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/openssl/errors.h"
#include "crunchy/internal/algs/openssl/openssl_unique_ptr.h"
#include "crunchy/internal/common/string_buffer.h"
#include "crunchy/util/status.h"
#include <openssl/mem.h>
#include <openssl/rsa.h>

namespace crunchy {

StatusOr<std::string> SerializePrivateKey(const RSA* rsa);

StatusOr<openssl_unique_ptr<RSA>> DeserializePrivateKey(
    absl::string_view serialized_private_key);

StatusOr<std::string> SerializePublicKey(const RSA* rsa);

StatusOr<openssl_unique_ptr<RSA>> DeserializePublicKey(
    absl::string_view serialized_public_key);

// Attempts to deserialize a public key from DER format to a public key in
// SubjectPublicKeyInfo PEM format.
StatusOr<std::string> DeserializeDerPublicKeyAsSubjectPublicKeyInfoPem(
    absl::string_view der_public_key);

// Attempts to deserialize a public key from SubjectPublicKeyInfo PEM format to
// a public key in DER format.
StatusOr<std::string> DeserializeSubjectPublicKeyInfoPemAsDerPublicKey(
    absl::string_view pem_public_key);

// Attempts to deserialize an RSA public key from DER format to RsaPublicKey
// PEM format.
StatusOr<std::string> DeserializeDerPublicKeyAsRsaPublicKeyPem(
    absl::string_view der_public_key);

// Attempts to deserialize a public key from RsaPublicKey PEM format to DER
// format.
StatusOr<std::string> DeserializeRsaPublicKeyPemAsDerPublicKey(
    absl::string_view pem_public_key);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_OPENSSL_RSA_H_
