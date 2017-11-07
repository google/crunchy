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

#include "crunchy/key_management/crunchy_factory.h"

#include "crunchy/crunchy_hybrid_crypter.h"
#include "crunchy/internal/keyset/aead_crypting_key_registry.h"
#include "crunchy/internal/keyset/crypter_factory.h"
#include "crunchy/internal/keyset/hybrid_crypter_factory.h"
#include "crunchy/internal/keyset/hybrid_crypting_key_registry.h"
#include "crunchy/internal/keyset/keyset_util.h"
#include "crunchy/internal/keyset/macer_factory.h"
#include "crunchy/internal/keyset/macing_key_registry.h"
#include "crunchy/internal/keyset/signer_factory.h"
#include "crunchy/internal/keyset/signing_key_registry.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

StatusOr<std::unique_ptr<CrunchyCrypter>> MakeCrunchyCrypter(
    const std::shared_ptr<KeysetHandle>& keyset_handle) {
  const AeadCryptingKeyRegistry& registry = GetAeadCryptingKeyRegistry();
  const Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return MakeCrunchyCrypter(registry, keyset);
}

StatusOr<std::unique_ptr<CrunchyHybridEncrypter>> MakeCrunchyHybridEncrypter(
    const std::shared_ptr<KeysetHandle>& keyset_handle) {
  const HybridCryptingKeyRegistry& registry = GetHybridCryptingKeyRegistry();
  Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return MakeCrunchyHybridEncrypter(registry, keyset);
}

StatusOr<std::unique_ptr<CrunchyHybridDecrypter>> MakeCrunchyHybridDecrypter(
    const std::shared_ptr<KeysetHandle>& keyset_handle) {
  const HybridCryptingKeyRegistry& registry = GetHybridCryptingKeyRegistry();
  Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return MakeCrunchyHybridDecrypter(registry, keyset);
}

StatusOr<std::unique_ptr<CrunchyMacer>> MakeCrunchyMacer(
        const std::shared_ptr<KeysetHandle>& keyset_handle) {
  const MacingKeyRegistry& registry = GetMacingKeyRegistry();
  const Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return MakeCrunchyMacer(registry, keyset);
}

StatusOr<std::unique_ptr<CrunchySigner>> MakeCrunchySigner(
    const std::shared_ptr<KeysetHandle>& keyset_handle) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return MakeCrunchySigner(registry, keyset);
}

StatusOr<std::unique_ptr<CrunchyVerifier>> MakeCrunchyVerifier(
    const std::shared_ptr<KeysetHandle>& keyset_handle) {
  const SigningKeyRegistry& registry = GetSigningKeyRegistry();
  Keyset keyset = KeysetUtil::KeysetHandleAsProto(keyset_handle);
  return MakeCrunchyVerifier(registry, keyset);
}

}  // namespace crunchy
