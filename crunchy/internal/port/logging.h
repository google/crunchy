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
#ifndef CRUNCHY_INTERNAL_PORT_LOGGING_H_
#define CRUNCHY_INTERNAL_PORT_LOGGING_H_

#include <memory>
#include <sstream>
#include <string>
#include "absl/strings/string_view.h"

// This file is based off the logging work by the bazel team in util/logging.h,
// which is in turn based off the logging work by the protobuf team in
// stubs/logging.h,
//
// Users of this logging library should use CRUNCHY_LOG(level) << ""; format,
// and specify how they wish to handle the output of the log messages by
// creating a LogHandler to pass to SetLogHandler().
namespace crunchy {

enum LogSeverity {
  INFO,
  WARNING,
  ERROR,
  FATAL,

#ifdef NDEBUG
  DFATAL = LogSeverity::ERROR
#else
  DFATAL = LogSeverity::FATAL
#endif
};

// Returns a std::string representation of the log level.
const char* LogLevelName(LogSeverity level);

namespace internal {

class LogFinisher;
class LogMessage {
 public:
  LogMessage(const char* filename, int line, LogSeverity level);
  ~LogMessage();

  LogMessage& operator<<(const std::string& value);
  LogMessage& operator<<(absl::string_view);
  LogMessage& operator<<(const char* value);
  LogMessage& operator<<(char value);
  LogMessage& operator<<(bool value);
  LogMessage& operator<<(short value);
  LogMessage& operator<<(int value);
  LogMessage& operator<<(unsigned int value);
  LogMessage& operator<<(long value);
  LogMessage& operator<<(unsigned long value);
  LogMessage& operator<<(long long value);
  LogMessage& operator<<(unsigned long long value);
  LogMessage& operator<<(float value);
  LogMessage& operator<<(double value);
  LogMessage& operator<<(long double value);
  LogMessage& operator<<(void* value);
  std::ostream& stream() { return message_; }

 private:
  LogSeverity level_;
  const char* filename_;
  int line_;
  std::stringstream message_;
};

// Used to make the entire "LOG(BLAH) << etc." expression have a void return
// type and print a newline after each message.
class LogFinisher {
 public:
  void operator=(LogMessage& other) {}
};

}  // namespace internal

#define CRUNCHY_LOG(LEVEL)                                              \
  ::crunchy::internal::LogFinisher() = ::crunchy::internal::LogMessage( \
      __FILE__, __LINE__, ::crunchy::LogSeverity::LEVEL)
#define CRUNCHY_LOG_IF(LEVEL, CONDITION) \
  !(CONDITION) ? (void)0 : CRUNCHY_LOG(LEVEL)

#define CRUNCHY_CHECK(EXPRESSION) \
  CRUNCHY_LOG_IF(FATAL, !(EXPRESSION)) << "CHECK failed: " #EXPRESSION ": "
#define CRUNCHY_CHECK_EQ(A, B) CRUNCHY_CHECK((A) == (B))
#define CRUNCHY_CHECK_NE(A, B) CRUNCHY_CHECK((A) != (B))
#define CRUNCHY_CHECK_LT(A, B) CRUNCHY_CHECK((A) < (B))
#define CRUNCHY_CHECK_LE(A, B) CRUNCHY_CHECK((A) <= (B))
#define CRUNCHY_CHECK_GT(A, B) CRUNCHY_CHECK((A) > (B))
#define CRUNCHY_CHECK_GE(A, B) CRUNCHY_CHECK((A) >= (B))

namespace internal {

template <typename T>
T&& CheckNotNull(T&& t) {
  CRUNCHY_CHECK(t != nullptr);
  return std::forward<T>(t);
}

#define CRUNCHY_CHECK_NOTNULL(EXPRESSION) \
  ::crunchy::internal::CheckNotNull((EXPRESSION))

}  // namespace internal

#ifdef NDEBUG

#define CRUNCHY_DLOG(LEVEL) CRUNCHY_LOG_IF(LEVEL, false)

#define CRUNCHY_DCHECK(EXPRESSION) \
  while (false) CRUNCHY_CHECK(EXPRESSION)
#define CRUNCHY_DCHECK_OK(E) CRUNCHY_DCHECK(::crunchy::internal::IsOk(E))
#define CRUNCHY_DCHECK_EQ(A, B) CRUNCHY_DCHECK((A) == (B))
#define CRUNCHY_DCHECK_NE(A, B) CRUNCHY_DCHECK((A) != (B))
#define CRUNCHY_DCHECK_LT(A, B) CRUNCHY_DCHECK((A) < (B))
#define CRUNCHY_DCHECK_LE(A, B) CRUNCHY_DCHECK((A) <= (B))
#define CRUNCHY_DCHECK_GT(A, B) CRUNCHY_DCHECK((A) > (B))
#define CRUNCHY_DCHECK_GE(A, B) CRUNCHY_DCHECK((A) >= (B))

#else  // NDEBUG

#define CRUNCHY_DLOG CRUNCHY_LOG

#define CRUNCHY_DCHECK CRUNCHY_CHECK
#define CRUNCHY_DCHECK_OK CRUNCHY_CHECK_OK
#define CRUNCHY_DCHECK_EQ CRUNCHY_CHECK_EQ
#define CRUNCHY_DCHECK_NE CRUNCHY_CHECK_NE
#define CRUNCHY_DCHECK_LT CRUNCHY_CHECK_LT
#define CRUNCHY_DCHECK_LE CRUNCHY_CHECK_LE
#define CRUNCHY_DCHECK_GT CRUNCHY_CHECK_GT
#define CRUNCHY_DCHECK_GE CRUNCHY_CHECK_GE

#endif  // !NDEBUG

class LogHandler {
 public:
  virtual ~LogHandler() {}
  virtual void HandleMessage(LogSeverity level, const std::string& filename,
                             int line, const std::string& message) = 0;
  virtual void SetOutputDir(const std::string& output_base) = 0;
};

// Sets the log handler that routes all log messages.
// SetLogHandler is not thread-safe.  You should only call it
// at initialization time, and probably not from library code.
void SetLogHandler(std::unique_ptr<LogHandler> new_handler);

// Sets the current handler's output directory, given that the Handler cares.
void SetLogfileDirectory(const std::string& output_dir);

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_PORT_LOGGING_H_
