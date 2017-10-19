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

#ifndef CRUNCHY_ALGS_MAC_MAC_INTERFACE_H_
#define CRUNCHY_ALGS_MAC_MAC_INTERFACE_H_

#include <stddef.h>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

// An interface for computing a cryptographic MAC.
class MacInterface {
 public:
  virtual ~MacInterface() = default;

  // Signs the given std::string and returns the signature.
  virtual StatusOr<std::string> Sign(absl::string_view input) const = 0;
  // Verifies a signature.
  virtual Status Verify(absl::string_view input,
                        absl::string_view signature) const = 0;
  // Returns the length of a signature
  virtual size_t GetSignatureLength() const = 0;
};

class MacFactory {
 public:
  virtual ~MacFactory() = default;

  virtual size_t GetKeyLength() const = 0;
  virtual size_t GetSignatureLength() const = 0;
  virtual StatusOr<std::unique_ptr<MacInterface>> Make(
      absl::string_view key) const = 0;
};

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_MAC_MAC_INTERFACE_H_
