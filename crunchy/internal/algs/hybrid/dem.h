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

#ifndef CRUNCHY_ALGS_HYBRID_DEM_H_
#define CRUNCHY_ALGS_HYBRID_DEM_H_

#include <stddef.h>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

class Dem {
 public:
  virtual ~Dem() = default;

  virtual StatusOr<std::string> Encrypt(absl::string_view plaintext) const = 0;
  virtual StatusOr<std::string> Decrypt(absl::string_view ciphertext) const = 0;
};

class DemFactory {
 public:
  virtual ~DemFactory() = default;

  virtual size_t GetKeyLength() const = 0;
  virtual size_t GetMaxCiphertextLength(size_t plaintext_length) const = 0;
  virtual size_t GetMaxPlaintextLength(size_t ciphertext_length) const = 0;
  virtual StatusOr<std::unique_ptr<Dem>> MakeDem(
      absl::string_view key) const = 0;
};

const DemFactory& GetAes128GcmDemFactory();
const DemFactory& GetAes256GcmDemFactory();

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HYBRID_DEM_H_
