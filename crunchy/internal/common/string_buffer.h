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

#ifndef CRUNCHY_INTERNAL_COMMON_STRING_BUFFER_H_
#define CRUNCHY_INTERNAL_COMMON_STRING_BUFFER_H_

#include <stddef.h>
#include <stdint.h>
#include <string>

#include "absl/strings/string_view.h"

namespace crunchy {

// A wrapper around std::string that has accessors which are convenient for use
// in APIs that interact with std::string, string_view, and uint8_t* arrays.
// The class is thread compatible, but not threadsafe.
class StringBuffer {
 public:
  // Preallocates an uninitialized std::string of a particular size.
  explicit StringBuffer(size_t buffer_size)
      : buffer_(std::string(buffer_size, 0x00)), limit_(buffer_size) {}

  // Creates a copy of string_view.
  explicit StringBuffer(absl::string_view s) : buffer_(s), limit_(s.size()) {}

  uint8_t* data() { return reinterpret_cast<uint8_t*>(&*buffer_.begin()); }

  std::string& as_string() {
    buffer_.resize(limit_);
    return buffer_;
  }

  absl::string_view as_string_view() {
    return absl::string_view(buffer_.data(), limit_);
  }

  size_t length() const { return limit_; }

  // The underlying std::string will be resized to this value on the next access.
  size_t* mutable_limit() { return &limit_; }

 private:
  std::string buffer_;
  size_t limit_;
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_COMMON_STRING_BUFFER_H_
