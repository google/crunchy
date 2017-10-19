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

#ifndef CRUNCHY_ALGS_CRYPT_AES_EAX_H_
#define CRUNCHY_ALGS_CRYPT_AES_EAX_H_

#include "crunchy/internal/algs/crypt/crypter_interface.h"

namespace crunchy {

// A class which implements the AES-EAX AEAD scheme in the CrypterInterface.
// This supports 128 and 256-bit AES keys. The NewInstance factory method can
// be used to create new instances of the class. Each instance has an associated
// key that cannot be modified later. Valid nonce lengths and tag lengths are
// 16 bytes.
const CrypterFactory& GetAes128EaxFactory();
const CrypterFactory& GetAes256EaxFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_CRYPT_AES_EAX_H_
