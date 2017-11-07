#ifndef CRUNCHY_INTERNAL_KEYSET_REGISTRY_H_
#define CRUNCHY_INTERNAL_KEYSET_REGISTRY_H_

#include "absl/strings/string_view.h"
#include "crunchy/key_management/internal/keyset.pb.h"
#include "crunchy/util/status.h"

namespace crunchy {

// Base class for all key registries.
class KeyRegistry {
 public:
  KeyRegistry() = default;
  virtual ~KeyRegistry() = default;

  KeyRegistry(const KeyRegistry&) = delete;

  virtual bool contains(const absl::string_view key_label) const = 0;

  virtual StatusOr<KeyData> CreateKeyData(
      const absl::string_view key_label) const = 0;
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_KEYSET_REGISTRY_H_
