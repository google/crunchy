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

// Copyright 2016 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is based off the logging work by the bazel and protobuf teams
#include "crunchy/internal/port/logging.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>

namespace crunchy {

const char* LogLevelName(LogSeverity level) {
  static const char* level_names[] = {"INFO", "WARNING", "ERROR", "FATAL"};
  CRUNCHY_CHECK(static_cast<int>(level) < 4)
      << "LogLevelName: level out of range, there are only 4 levels.";
  return level_names[level];
}

namespace internal {

namespace {
LogHandler* log_handler_ = nullptr;
}

LogMessage::LogMessage(const char* filename, int line, LogSeverity level)
    : level_(level), filename_(filename), line_(line) {}

#undef DECLARE_STREAM_OPERATOR
#define DECLARE_STREAM_OPERATOR(TYPE)              \
  LogMessage& LogMessage::operator<<(TYPE value) { \
    message_ << value;                             \
    return *this;                                  \
  }

DECLARE_STREAM_OPERATOR(const std::string&)
DECLARE_STREAM_OPERATOR(absl::string_view)
DECLARE_STREAM_OPERATOR(const char*)
DECLARE_STREAM_OPERATOR(char)
DECLARE_STREAM_OPERATOR(bool)
DECLARE_STREAM_OPERATOR(short)
DECLARE_STREAM_OPERATOR(int)
DECLARE_STREAM_OPERATOR(unsigned int)
DECLARE_STREAM_OPERATOR(long)
DECLARE_STREAM_OPERATOR(unsigned long)
DECLARE_STREAM_OPERATOR(long long)
DECLARE_STREAM_OPERATOR(unsigned long long)
DECLARE_STREAM_OPERATOR(float)
DECLARE_STREAM_OPERATOR(double)
DECLARE_STREAM_OPERATOR(long double)
DECLARE_STREAM_OPERATOR(void*)
#undef DECLARE_STREAM_OPERATOR

LogMessage::~LogMessage() {
  std::string message(message_.str());
  if (log_handler_ != nullptr) {
    log_handler_->HandleMessage(level_, filename_, line_, message);
  } else if (level_ == FATAL) {
    // Expect the log_handler_ to handle FATAL calls, but we should still fail
    // as expected even if no log_handler_ is defined. For ease of debugging,
    // we also print out the error statement.
    std::cerr << filename_ << ":" << line_ << " FATAL: " << message
              << std::endl;
    std::abort();
  } else {
    std::cerr << filename_ << ":" << line_ << " " << LogLevelName(level_)
              << ": " << message << std::endl;
  }
}

}  // namespace internal

void SetLogHandler(std::unique_ptr<LogHandler> new_handler) {
  CRUNCHY_CHECK_NE(internal::log_handler_, nullptr);
  internal::log_handler_ = new_handler.release();
}

void SetLogfileDirectory(const std::string& output_dir) {
  if (internal::log_handler_ != nullptr) {
    internal::log_handler_->SetOutputDir(output_dir);
  }
}

}  // namespace crunchy
