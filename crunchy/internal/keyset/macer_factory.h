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

#ifndef CRUNCHY_INTERNAL_KEYSET_MACER_FACTORY_H_
#define CRUNCHY_INTERNAL_KEYSET_MACER_FACTORY_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "crunchy/crunchy_macer.h"
#include "crunchy/internal/keyset/macing_key_registry.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/key_management/keyset_handle.h"
#include "crunchy/util/status.h"

namespace crunchy {

StatusOr<std::unique_ptr<CrunchyMacer>> MakeCrunchyMacer(
    const MacingKeyRegistry& registry, const Keyset& keyset);

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYSET_MACER_FACTORY_H_
