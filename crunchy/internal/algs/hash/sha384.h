#ifndef CRUNCHY_ALGS_HASH_SHA384_H_
#define CRUNCHY_ALGS_HASH_SHA384_H_

#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

StatusOr<std::string> Sha384Hash(absl::string_view input);

}  // namespace crunchy

#endif  // CRUNCHY_ALGS_HASH_SHA384_H_
