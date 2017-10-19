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

#ifndef CRUNCHY_KEY_MANAGEMENT_CRUNCHY_FACTORY_H_
#define CRUNCHY_KEY_MANAGEMENT_CRUNCHY_FACTORY_H_

#include "crunchy/crunchy_crypter.h"
#include "crunchy/crunchy_hybrid_crypter.h"
#include "crunchy/crunchy_macer.h"
#include "crunchy/crunchy_signer.h"
#include "crunchy/key_management/keyset_handle.h"

namespace crunchy {

// Symmetric Encryption
StatusOr<std::unique_ptr<CrunchyCrypter>> MakeCrunchyCrypter(
    const std::shared_ptr<KeysetHandle>& keyset_handle);

// Hybrid Encryption
StatusOr<std::unique_ptr<CrunchyHybridEncrypter>> MakeCrunchyHybridEncrypter(
    const std::shared_ptr<KeysetHandle>& keyset_handle);

StatusOr<std::unique_ptr<CrunchyHybridDecrypter>> MakeCrunchyHybridDecrypter(
    const std::shared_ptr<KeysetHandle>& keyset_handle);

StatusOr<std::unique_ptr<CrunchyMacer>> MakeCrunchyMacer(
        const std::shared_ptr<KeysetHandle>& keyset_handle);

StatusOr<std::unique_ptr<CrunchySigner>> MakeCrunchySigner(
        const std::shared_ptr<KeysetHandle>& keyset_handle);

StatusOr<std::unique_ptr<CrunchyVerifier>> MakeCrunchyVerifier(
        const std::shared_ptr<KeysetHandle>& keyset_handle);


}  // namespace crunchy

#endif  // CRUNCHY_KEY_MANAGEMENT_CRUNCHY_FACTORY_H_
