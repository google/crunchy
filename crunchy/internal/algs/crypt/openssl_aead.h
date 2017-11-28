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

#ifndef CRUNCHY_ALGS_CRYPT_OPENSSL_AEAD_H_
#define CRUNCHY_ALGS_CRYPT_OPENSSL_AEAD_H_

#include "crunchy/internal/algs/crypt/crypter_base.h"
#include "crunchy/internal/algs/crypt/crypter_interface.h"
#include "crunchy/util/status.h"

namespace crunchy {

// AES-GCM using a 96-bit random nonce, 128-bit tag, and either AES-128 or
// AES-256.
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
const CrypterFactory& GetAes128GcmFactory();
const CrypterFactory& GetAes256GcmFactory();

// ChaCha Poly1305 with a 96-bit random nonce, 128-bit tag, and 256-bit key.
// https://tools.ietf.org/html/rfc7539
const CrypterFactory& GetChaCha20Poly1305Factory();

// AES-GCM-SIV using a 96-bit random nonce, 128-bit tag, and either AES-128 or
// AES-256.
// https://tools.ietf.org/html/draft-irtf-cfrg-gcmsiv-06
const CrypterFactory& GetAes128GcmSivFactory();
const CrypterFactory& GetAes256GcmSivFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_CRYPT_OPENSSL_AEAD_H_
