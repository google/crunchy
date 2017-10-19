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

#include "crunchy/internal/algs/openssl/errors.h"

#include <stdint.h>

#include "absl/strings/str_cat.h"
#include <openssl/err.h>

namespace crunchy {

bool HasOpensslErrors() { return ERR_peek_error() != 0; }
std::string GetOpensslErrors() {
  uint32_t error = ERR_get_error();
  if (error == 0) {
    return "ERR_get_error() returned no error";
  }
  char error_buffer[ERR_ERROR_STRING_BUF_LEN];
  std::string error_result;
  while (error != 0) {
    ERR_error_string_n(error, error_buffer, sizeof(error_buffer));
    error = ERR_get_error();
    if (error == 0) {
      absl::StrAppend(&error_result, error_buffer);
    } else {
      absl::StrAppend(&error_result, error_buffer, ", ");
    }
  }
  return error_result;
}

}  // namespace crunchy
