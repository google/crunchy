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

#ifndef CRUNCHY_UTIL_STATUS_H_
#define CRUNCHY_UTIL_STATUS_H_

#include <string>
#include <utility>

#include "absl/base/attributes.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/port/port.h"


namespace crunchy {

enum Code {
  // Not an error, returned on success
  OK = 0,

  // The operation was cancelled, typically by the caller.
  CANCELLED = 1,

  // Unknown error.  For example, this error may be returned when
  // a Status value received from another address space belongs to
  // an error-space that is not known in this address space.  Also
  // errors raised by APIs that do not return enough error information
  // may be converted to this error.
  UNKNOWN = 2,

  // The client specified an invalid argument.  Note that this differs
  // from FAILED_PRECONDITION.  INVALID_ARGUMENT indicates arguments
  // that are problematic regardless of the state of the system
  // (e.g., a malformed file name).
  INVALID_ARGUMENT = 3,

  // The deadline expired before the operation could complete. For operations
  // that change the state of the system, this error may be returned
  // even if the operation has completed successfully.  For example, a
  // successful response from a server could have been delayed long
  // enough for the deadline to expire.
  DEADLINE_EXCEEDED = 4,

  // Some requested entity (e.g., file or directory) was not found.
  //
  // Note to server developers: if a request is denied for an entire class
  // of users, such as gradual feature rollout or undocumented whitelist,
  // `NOT_FOUND` may be used. If a request is denied for some users within
  // a class of users, such as user-based access control, `PERMISSION_DENIED`
  // must be used.
  NOT_FOUND = 5,

  // The entity that a client attempted to create (e.g., file or directory)
  // already exists.
  ALREADY_EXISTS = 6,

  // The caller does not have permission to execute the specified
  // operation. `PERMISSION_DENIED` must not be used for rejections
  // caused by exhausting some resource (use `RESOURCE_EXHAUSTED`
  // instead for those errors). `PERMISSION_DENIED` must not be
  // used if the caller can not be identified (use `UNAUTHENTICATED`
  // instead for those errors). This error code does not imply the
  // request is valid or the requested entity exists or satisfies
  // other pre-conditions.
  PERMISSION_DENIED = 7,

  // The request does not have valid authentication credentials for the
  // operation.
  UNAUTHENTICATED = 16,

  // Some resource has been exhausted, perhaps a per-user quota, or
  // perhaps the entire file system is out of space.
  RESOURCE_EXHAUSTED = 8,

  // The operation was rejected because the system is not in a state
  // required for the operation's execution.  For example, the directory
  // to be deleted is non-empty, an rmdir operation is applied to
  // a non-directory, etc.
  //
  // A litmus test that may help a service implementor in deciding
  // between FAILED_PRECONDITION, ABORTED, and UNAVAILABLE:
  //  (a) Use UNAVAILABLE if the client can retry just the failing call.
  //  (b) Use ABORTED if the client should retry at a higher-level
  //      (e.g., when a client-specified test-and-set fails, indicating the
  //      client should restart a read-modify-write sequence).
  //  (c) Use FAILED_PRECONDITION if the client should not retry until
  //      the system state has been explicitly fixed.  E.g., if an "rmdir"
  //      fails because the directory is non-empty, FAILED_PRECONDITION
  //      should be returned since the client should not retry unless
  //      the files are deleted from the directory.
  FAILED_PRECONDITION = 9,

  // The operation was aborted, typically due to a concurrency issue such as
  // a sequencer check failure or transaction abort.
  //
  // See litmus test above for deciding between FAILED_PRECONDITION,
  // ABORTED, and UNAVAILABLE.
  ABORTED = 10,

  // The operation was attempted past the valid range.  E.g., seeking or
  // reading past end-of-file.
  //
  // Unlike INVALID_ARGUMENT, this error indicates a problem that may
  // be fixed if the system state changes. For example, a 32-bit file
  // system will generate INVALID_ARGUMENT if asked to read at an
  // offset that is not in the range [0,2^32-1], but it will generate
  // OUT_OF_RANGE if asked to read from an offset past the current
  // file size.
  //
  // There is a fair bit of overlap between FAILED_PRECONDITION and
  // OUT_OF_RANGE.  We recommend using OUT_OF_RANGE (the more specific
  // error) when it applies so that callers who are iterating through
  // a space can easily look for an OUT_OF_RANGE error to detect when
  // they are done.
  OUT_OF_RANGE = 11,

  // The operation is not implemented or is not supported/enabled in this
  // service.
  UNIMPLEMENTED = 12,

  // Internal errors.  This means that some invariants expected by the
  // underlying system have been broken.  This error code is reserved
  // for serious errors.
  INTERNAL = 13,

  // The service is currently unavailable.  This is most likely a
  // transient condition, which can be corrected by retrying with
  // a backoff.
  //
  // See litmus test above for deciding between FAILED_PRECONDITION,
  // ABORTED, and UNAVAILABLE.
  UNAVAILABLE = 14,

  // Unrecoverable data loss or corruption.
  DATA_LOSS = 15,

  // An extra enum entry to prevent people from writing code that
  // fails to compile when a new code is added.
  //
  // Nobody should ever reference this enumeration entry. In particular,
  // if you write C++ code that switches on this enumeration, add a default:
  // case instead of a case that mentions this enumeration entry.
  //
  // Nobody should rely on the value (currently 20) listed here.  It
  // may change in the future.
  DO_NOT_USE_RESERVED_FOR_FUTURE_EXPANSION_USE_DEFAULT_IN_SWITCH_INSTEAD_ = 20,
};

class ABSL_MUST_USE_RESULT Status {
 public:
  Status() : code_(Code::OK) {}
  Status(Code code, absl::string_view msg) : code_(code), msg_(std::string(msg)) {}

  bool ok() const { return code_ == Code::OK; }
  bool operator==(const Status& x) const {
    return code_ == x.code_ && msg_ == x.msg_;
  }

  Code error_code() const { return code_; }
  const std::string& error_message() const { return msg_; }

  std::string ToString() const { return msg_; }

  void IgnoreError() {}

 private:
  Code code_;
  std::string msg_;
};

inline Status OkStatus() { return Status(); }

inline std::ostream& operator<<(std::ostream& os, const Status& x) {
  os << x.ToString();
  return os;
}

class ABSL_MUST_USE_RESULT StatusBuilder {
 public:
  StatusBuilder(Code code, source_location location)
      : status_(code, ""),
        line_(location.line()),
        file_(location.file_name()),
        log_severity_(INFO),
        log_verbose_level_(0),
        log_type_(LogType::kDisabled) {}

  StatusBuilder& Log(LogSeverity severity) {
    if (status_.ok()) return *this;
    log_type_ = LogType::kLog;
    log_severity_ = severity;
    return *this;
  }

  StatusBuilder& VLog(int level) {
    if (status_.ok()) return *this;
    log_type_ = LogType::kVLog;
    log_verbose_level_ = level;
    return *this;
  }

  StatusBuilder& LogError() { return Log(ERROR); }
  StatusBuilder& LogWarning() { return Log(WARNING); }
  StatusBuilder& LogInfo() { return Log(INFO); }

  StatusBuilder& operator<<(absl::string_view value) {
    stream_.append(value.data(), value.size());
    return *this;
  }

  template <typename T>
  StatusBuilder& operator<<(const T& value) {
    absl::StrAppend(&stream_, value);
    return *this;
  }

  operator Status() const& {
    Status status(status_.error_code(), stream_);
    if (log_type_ == LogType::kDisabled) return status;
    ::crunchy::internal::LogMessage log_message(file_, line_, log_severity_);
    log_message.stream() << status;
    return status;
  }

  int line() const { return line_; }
  const char* file() const { return file_; }

 private:
  enum class LogType {
    kDisabled,
    kLog,
    kVLog,
  };

  Status status_;
  int line_;
  const char* file_;
  LogSeverity log_severity_;
  int log_verbose_level_;
  LogType log_type_;
  std::string stream_;
};

template <typename T>
class ABSL_MUST_USE_RESULT StatusOr {
 public:
  StatusOr(const Status& status) : status_(status) { EnsureNotOk(); }
  StatusOr(const StatusBuilder& status_builder) : status_(status_builder) {
    EnsureNotOk();
  }
  StatusOr(const T& value) : value_(value) {}
  StatusOr(T&& value) : value_(std::move(value)) {}

  const Status& status() const { return status_; }
  bool ok() const { return status_.ok(); }

  operator Status() const& { return status_; }

  const T& ValueOrDie() const& {
    EnsureOk();
    return value_;
  }

  T& ValueOrDie() & {
    EnsureOk();
    return value_;
  }

  const T&& ValueOrDie() const&& {
    EnsureOk();
    return std::move(value_);
  }

  T&& ValueOrDie() && {
    EnsureOk();
    return std::move(value_);
  }

 private:
  void EnsureNotOk() {
    if (ok()) {
      CRUNCHY_DLOG(FATAL) << "StatusOr constructed with an ok status";
      status_ = Status(INTERNAL, "StatusOr constructed with an ok status");
    }
  }
  void EnsureOk() const {
    if (!ok()) {
      CRUNCHY_LOG(FATAL) << "ValueOrDie() called with error status: "
                         << status_.ToString();
    }
  }
  Status status_;
  T value_;
};

template <typename T>
inline std::ostream& operator<<(std::ostream& os, const StatusOr<T>& x) {
  os << x.status().ToString();
  return os;
}

inline StatusBuilder AbortedErrorBuilder(source_location location) {
  return StatusBuilder(Code::ABORTED, location);
}

inline StatusBuilder AlreadyExistsErrorBuilder(source_location location) {
  return StatusBuilder(Code::ALREADY_EXISTS, location);
}

inline StatusBuilder CancelledErrorBuilder(source_location location) {
  return StatusBuilder(Code::CANCELLED, location);
}

inline StatusBuilder DataLossErrorBuilder(source_location location) {
  return StatusBuilder(Code::DATA_LOSS, location);
}

inline StatusBuilder DeadlineExceededErrorBuilder(
    source_location location) {
  return StatusBuilder(Code::DEADLINE_EXCEEDED, location);
}

inline StatusBuilder FailedPreconditionErrorBuilder(
    source_location location) {
  return StatusBuilder(Code::FAILED_PRECONDITION, location);
}

inline StatusBuilder InternalErrorBuilder(source_location location) {
  return StatusBuilder(Code::INTERNAL, location);
}

inline StatusBuilder InvalidArgumentErrorBuilder(
    source_location location) {
  return StatusBuilder(Code::INVALID_ARGUMENT, location);
}

inline StatusBuilder NotFoundErrorBuilder(source_location location) {
  return StatusBuilder(Code::NOT_FOUND, location);
}

inline StatusBuilder OutOfRangeErrorBuilder(source_location location) {
  return StatusBuilder(Code::OUT_OF_RANGE, location);
}

inline StatusBuilder PermissionDeniedErrorBuilder(
    source_location location) {
  return StatusBuilder(Code::PERMISSION_DENIED, location);
}

inline StatusBuilder UnauthenticatedErrorBuilder(
    source_location location) {
  return StatusBuilder(Code::UNAUTHENTICATED, location);
}

inline StatusBuilder ResourceExhaustedErrorBuilder(
    source_location location) {
  return StatusBuilder(Code::RESOURCE_EXHAUSTED, location);
}

inline StatusBuilder UnavailableErrorBuilder(source_location location) {
  return StatusBuilder(Code::UNAVAILABLE, location);
}

inline StatusBuilder UnimplementedErrorBuilder(source_location location) {
  return StatusBuilder(Code::UNIMPLEMENTED, location);
}

inline StatusBuilder UnknownErrorBuilder(source_location location) {
  return StatusBuilder(Code::UNKNOWN, location);
}

inline Status AbortedError(absl::string_view error_message) {
  return Status(Code::ABORTED, error_message);
}

inline Status AlreadyExistsError(absl::string_view error_message) {
  return Status(Code::ALREADY_EXISTS, error_message);
}

inline Status CancelledError(absl::string_view error_message) {
  return Status(Code::CANCELLED, error_message);
}

inline Status DataLossError(absl::string_view error_message) {
  return Status(Code::DATA_LOSS, error_message);
}

inline Status DeadlineExceededError(absl::string_view error_message) {
  return Status(Code::DEADLINE_EXCEEDED, error_message);
}

inline Status FailedPreconditionError(absl::string_view error_message) {
  return Status(Code::FAILED_PRECONDITION, error_message);
}

inline Status InternalError(absl::string_view error_message) {
  return Status(Code::INTERNAL, error_message);
}

inline Status InvalidArgumentError(absl::string_view error_message) {
  return Status(Code::INVALID_ARGUMENT, error_message);
}

inline Status NotFoundError(absl::string_view error_message) {
  return Status(Code::NOT_FOUND, error_message);
}

inline Status OutOfRangeError(absl::string_view error_message) {
  return Status(Code::OUT_OF_RANGE, error_message);
}

inline Status PermissionDeniedError(absl::string_view error_message) {
  return Status(Code::PERMISSION_DENIED, error_message);
}

inline Status UnauthenticatedError(absl::string_view error_message) {
  return Status(Code::UNAUTHENTICATED, error_message);
}

inline Status ResourceExhaustedError(absl::string_view error_message) {
  return Status(Code::RESOURCE_EXHAUSTED, error_message);
}

inline Status UnavailableError(absl::string_view error_message) {
  return Status(Code::UNAVAILABLE, error_message);
}

inline Status UnimplementedError(absl::string_view error_message) {
  return Status(Code::UNIMPLEMENTED, error_message);
}

inline Status UnknownError(absl::string_view error_message) {
  return Status(Code::UNKNOWN, error_message);
}

}  // namespace crunchy

#endif  // CRUNCHY_UTIL_STATUS_H_
