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

#ifndef CRUNCHY_INTERNAL_PORT_PORT_OSS_H_
#define CRUNCHY_INTERNAL_PORT_PORT_OSS_H_

#include <string.h>

#include <sstream>
#include <string>
#include "crunchy/internal/port/logging.h"
#include "crunchy/internal/port/source_location.h"

namespace crunchy {

inline uint64_t BigEndianLoad64(const void* p) {
  uint8_t tmp[sizeof(uint64_t)];
  memcpy(tmp, p, sizeof(tmp));
  uint64_t result = static_cast<uint64_t>(tmp[0]) << 56 |
                    static_cast<uint64_t>(tmp[1]) << 48 |
                    static_cast<uint64_t>(tmp[2]) << 40 |
                    static_cast<uint64_t>(tmp[3]) << 32 |
                    static_cast<uint64_t>(tmp[4]) << 24 |
                    static_cast<uint64_t>(tmp[5]) << 16 |
                    static_cast<uint64_t>(tmp[6]) << 8 |
                    static_cast<uint64_t>(tmp[7]);
  return result;
}
inline void BigEndianStore64(void* p, uint64_t v) {
  uint8_t tmp[sizeof(uint64_t)];
  tmp[0] = static_cast<uint8_t>((v >> 56) & 0xFF);
  tmp[1] = static_cast<uint8_t>((v >> 48) & 0xFF);
  tmp[2] = static_cast<uint8_t>((v >> 40) & 0xFF);
  tmp[3] = static_cast<uint8_t>((v >> 32) & 0xFF);
  tmp[4] = static_cast<uint8_t>((v >> 24) & 0xFF);
  tmp[5] = static_cast<uint8_t>((v >> 16) & 0xFF);
  tmp[6] = static_cast<uint8_t>((v >> 8) & 0xFF);
  tmp[7] = static_cast<uint8_t>(v & 0xFF);
  memcpy(p, tmp, sizeof(tmp));
}

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_PORT_PORT_OSS_H_
