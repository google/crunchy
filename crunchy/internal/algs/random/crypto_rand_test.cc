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

#include <gtest/gtest.h>

namespace crunchy {

namespace {

TEST(CryptoRandTest, RandBytes) {
  const size_t array_size = 1024;
  char some_bytes[array_size];
  RandBytes(some_bytes, sizeof(some_bytes));
  char more_bytes[array_size];
  RandBytes(more_bytes, sizeof(more_bytes));
  EXPECT_NE(std::string(some_bytes, sizeof(some_bytes)),
            std::string(more_bytes, sizeof(more_bytes)));
}

TEST(CryptoRandTest, RandString) {
  std::string some_string = RandString(1024);
  std::string another_string = RandString(1024);

  EXPECT_NE(some_string, another_string);
}

TEST(CryptoRandTest, Rand8) {
  const size_t array_size = 1024;
  uint8_t some_ints[array_size];
  uint8_t more_ints[array_size];
  for (size_t i = 0; i < array_size; i++) some_ints[i] = Rand8();
  for (size_t i = 0; i < array_size; i++) more_ints[i] = Rand8();

  uint8_t result = 0;
  for (size_t i = 0; i < array_size; i++) result |= some_ints[i] ^ more_ints[i];
  EXPECT_NE(result, 0);
}

TEST(CryptoRandTest, Rand16) {
  const size_t array_size = 512;
  uint16_t some_ints[array_size];
  uint16_t more_ints[array_size];
  for (size_t i = 0; i < array_size; i++) some_ints[i] = Rand16();
  for (size_t i = 0; i < array_size; i++) more_ints[i] = Rand16();

  uint16_t result = 0;
  for (size_t i = 0; i < array_size; i++) result |= some_ints[i] ^ more_ints[i];
  EXPECT_NE(result, 0);
}

TEST(CryptoRandTest, Rand32) {
  const size_t array_size = 256;
  uint32_t some_ints[array_size];
  uint32_t more_ints[array_size];
  for (size_t i = 0; i < array_size; i++) some_ints[i] = Rand32();
  for (size_t i = 0; i < array_size; i++) more_ints[i] = Rand32();

  uint32_t result = 0;
  for (size_t i = 0; i < array_size; i++) result |= some_ints[i] ^ more_ints[i];
  EXPECT_NE(result, 0);
}

TEST(CryptoRandTest, Rand64) {
  const size_t array_size = 128;
  uint64_t some_ints[array_size];
  uint64_t more_ints[array_size];
  for (size_t i = 0; i < array_size; i++) some_ints[i] = Rand64();
  for (size_t i = 0; i < array_size; i++) more_ints[i] = Rand64();

  uint64_t result = 0;
  for (size_t i = 0; i < array_size; i++) result |= some_ints[i] ^ more_ints[i];
  EXPECT_NE(result, 0);
}

}  // namespace

}  // namespace crunchy
