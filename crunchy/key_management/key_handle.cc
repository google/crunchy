#include "crunchy/key_management/key_handle.h"

#include "crunchy/key_management/internal/keyset.pb.h"

namespace crunchy {

StatusOr<std::shared_ptr<KeyHandle>> KeyHandle::CloneAsPublicOnly() const {
  auto cloned_key_handle = std::make_shared<Key>(*key_);
  if (cloned_key_handle->mutable_data()->public_key().empty()) {
    return FailedPreconditionError(
        "Failed to Clone Key as public-only. Key does not contain public key "
        "data.");
  }
  if (cloned_key_handle->mutable_data()->private_key().empty()) {
    return FailedPreconditionError(
        "Failed to Clone Key. Key does not contain private key data. Maybe "
        "the keyset is already public-only?");
  }
  cloned_key_handle->mutable_data()->clear_private_key();
  return std::make_shared<KeyHandle>(cloned_key_handle);
}

const KeyMetadata& KeyHandle::metadata() const { return key_->metadata(); }

}  // namespace crunchy
