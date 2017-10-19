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

#include "crunchy/internal/algs/random/crypto_rand.h"
#include <openssl/rand.h>
#include <string.h>

namespace crunchy {
void RandBytes(void* out, size_t len) {
  RAND_bytes(reinterpret_cast<uint8_t*>(out), len);
}

uint8_t Rand8() {
  uint8_t result[1];
  RandBytes(result, sizeof(result));
  return result[0];
}
uint16_t Rand16() {
  uint8_t buffer[sizeof(uint16_t)];
  RandBytes(buffer, sizeof(buffer));
  uint16_t result;
  memcpy(&result, buffer, sizeof(buffer));
  return result;
}
uint32_t Rand32() {
  uint8_t buffer[sizeof(uint32_t)];
  RandBytes(buffer, sizeof(buffer));
  uint32_t result;
  memcpy(&result, buffer, sizeof(buffer));
  return result;
}
uint64_t Rand64() {
  uint8_t buffer[sizeof(uint64_t)];
  RandBytes(buffer, sizeof(buffer));
  uint64_t result;
  memcpy(&result, buffer, sizeof(buffer));
  return result;
}
std::string RandString(size_t len) {
  std::string result;
  result.resize(len);
  RandBytes(reinterpret_cast<uint8_t*>(&*result.begin()), len);
  return result;
}

}  // namespace crunchy
