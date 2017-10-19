#ifndef CRUNCHY_ALGS_HASH_SHA512_H_
#define CRUNCHY_ALGS_HASH_SHA512_H_

#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

StatusOr<std::string> Sha512Hash(absl::string_view input);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HASH_SHA512_H_
