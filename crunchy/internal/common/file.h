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

#ifndef CRUNCHY_INTERNAL_COMMON_FILE_H_
#define CRUNCHY_INTERNAL_COMMON_FILE_H_

#include <fstream>
#include <string>

#include "absl/strings/string_view.h"
#include "crunchy/util/status.h"

namespace crunchy {

inline Status GetFile(absl::string_view path, std::string* contents) {
  std::ifstream ifs((std::string(path)));
  if (!ifs) {
    return NotFoundErrorBuilder(CRUNCHY_LOC).LogInfo()
           << "Couldn't find file " << path;
  }
  contents->assign((std::istreambuf_iterator<char>(ifs)),
                   (std::istreambuf_iterator<char>()));
  return OkStatus();
}

inline Status SetFile(absl::string_view path, absl::string_view contents) {
  std::ofstream ofs((std::string(path)));
  ofs.write(contents.data(), contents.size());
  return OkStatus();
}

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_COMMON_FILE_H_
