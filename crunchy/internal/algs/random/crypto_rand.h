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

#ifndef CRUNCHY_ALGS_RANDOM_CRYPTO_RAND_H_
#define CRUNCHY_ALGS_RANDOM_CRYPTO_RAND_H_

#include <stddef.h>
#include <stdint.h>
#include <string>

namespace crunchy {

// All methods are threadsafe.
void RandBytes(void* out, size_t len);
uint8_t Rand8();
uint16_t Rand16();
uint32_t Rand32();
uint64_t Rand64();
std::string RandString(size_t len);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_RANDOM_CRYPTO_RAND_H_
