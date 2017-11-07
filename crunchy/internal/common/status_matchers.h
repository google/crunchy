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

// Testing utilities for working with ::crunchy::Status and ::crunchy::StatusOr.
//
// This is a fork of (a subset of) google3's util::Status matchers.

#ifndef CRUNCHY_INTERNAL_COMMON_STATUS_MATCHERS_H_
#define CRUNCHY_INTERNAL_COMMON_STATUS_MATCHERS_H_

#include <ostream>  // NOLINT
#include <string>
#include <type_traits>
#include <utility>

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>
#include "crunchy/internal/port/port.h"
#include "crunchy/util/status.h"

namespace testing {
namespace crunchy_status {
namespace internal_crunchy_status {

inline const ::crunchy::Status& GetStatus(const ::crunchy::Status& status) {
  return status;
}

template <typename T>
const ::crunchy::Status& GetStatus(const ::crunchy::StatusOr<T>& status) {
  return status.status();
}

////////////////////////////////////////////////////////////
// Implementation of IsOkAndHolds().

// Monomorphic implementation of matcher IsOkAndHolds(m).  StatusOrType can be
// either StatusOr<T> or a reference to it.
template <typename StatusOrType>
class IsOkAndHoldsMatcherImpl : public MatcherInterface<StatusOrType> {
 public:
  typedef typename std::remove_reference<StatusOrType>::type::element_type
      value_type;

  template <typename InnerMatcher>
  explicit IsOkAndHoldsMatcherImpl(InnerMatcher&& inner_matcher)
      : inner_matcher_(SafeMatcherCast<const value_type&>(
            std::forward<InnerMatcher>(inner_matcher))) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is OK and has a value that ";
    inner_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "isn't OK or has a value that ";
    inner_matcher_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(StatusOrType actual_value,
                       MatchResultListener* result_listener) const override {
    if (!actual_value.ok()) {
      *result_listener << "which has status " << actual_value.status();
      return false;
    }

    StringMatchResultListener inner_listener;
    const bool matches = inner_matcher_.MatchAndExplain(
        actual_value.ValueOrDie(), &inner_listener);
    const std::string inner_explanation = inner_listener.str();
    if (inner_explanation != "") {
      *result_listener << "which contains value "
                       << PrintToString(actual_value.ValueOrDie()) << ", "
                       << inner_explanation;
    }
    return matches;
  }

 private:
  const Matcher<const value_type&> inner_matcher_;
};

// Implements IsOkAndHolds(m) as a polymorphic matcher.
template <typename InnerMatcher>
class IsOkAndHoldsMatcher {
 public:
  explicit IsOkAndHoldsMatcher(InnerMatcher inner_matcher)
      : inner_matcher_(std::move(inner_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  StatusOrType can be either StatusOr<T> or a
  // reference to StatusOr<T>.
  template <typename StatusOrType>
  operator Matcher<StatusOrType>() const {
    return MakeMatcher(
        new IsOkAndHoldsMatcherImpl<StatusOrType>(inner_matcher_));
  }

 private:
  const InnerMatcher inner_matcher_;
};

////////////////////////////////////////////////////////////
// Implementation of StatusIs().

inline Matcher<int> ToCodeMatcher(const Matcher<int>& m) { return m; }

// StatusIs() is a polymorphic matcher.  This class is the common
// implementation of it shared by all types T where StatusIs() can be
// used as a Matcher<T>.
class StatusIsMatcherCommonImpl {
 public:
  StatusIsMatcherCommonImpl(Matcher<int> code_matcher,
                            Matcher<const std::string&> message_matcher)
      : code_matcher_(std::move(code_matcher)),
        message_matcher_(std::move(message_matcher)) {}

  void DescribeTo(std::ostream* os) const;

  void DescribeNegationTo(std::ostream* os) const;

  bool MatchAndExplain(const ::crunchy::Status& status,
                       MatchResultListener* result_listener) const;

 private:
  const Matcher<int> code_matcher_;
  const Matcher<const std::string&> message_matcher_;
};

// Monomorphic implementation of matcher StatusIs() for a given type
// T.  T can be Status, StatusOr<>, or a reference to either of them.
template <typename T>
class MonoStatusIsMatcherImpl : public MatcherInterface<T> {
 public:
  explicit MonoStatusIsMatcherImpl(StatusIsMatcherCommonImpl common_impl)
      : common_impl_(std::move(common_impl)) {}

  void DescribeTo(std::ostream* os) const override {
    common_impl_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    common_impl_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(T actual_value,
                       MatchResultListener* result_listener) const override {
    return common_impl_.MatchAndExplain(GetStatus(actual_value),
                                        result_listener);
  }

 private:
  StatusIsMatcherCommonImpl common_impl_;
};

// Implements StatusIs() as a polymorphic matcher.
class StatusIsMatcher {
 public:
  template <typename StatusCodeMatcher>
  StatusIsMatcher(StatusCodeMatcher&& code_matcher,
                  Matcher<const std::string&> message_matcher)
      : common_impl_(
            ToCodeMatcher(std::forward<StatusCodeMatcher>(code_matcher)),
            std::move(message_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  T can be StatusOr<>, Status, or a reference to
  // either of them.
  template <typename T>
  operator Matcher<T>() const {
    return MakeMatcher(new MonoStatusIsMatcherImpl<T>(common_impl_));
  }

 private:
  const StatusIsMatcherCommonImpl common_impl_;
};

// Monomorphic implementation of matcher IsOk() for a given type T.
// T can be Status, StatusOr<>, or a reference to either of them.
template <typename T>
class MonoIsOkMatcherImpl : public MatcherInterface<T> {
 public:
  void DescribeTo(std::ostream* os) const override { *os << "is OK"; }
  void DescribeNegationTo(std::ostream* os) const override {
    *os << "is not OK";
  }
  bool MatchAndExplain(T actual_value, MatchResultListener*) const override {
    return GetStatus(actual_value).ok();
  }
};

// Implements IsOk() as a polymorphic matcher.
class IsOkMatcher {
 public:
  template <typename T>
  operator Matcher<T>() const {  // NOLINT
    return MakeMatcher(new MonoIsOkMatcherImpl<T>());
  }
};

}  // namespace internal_crunchy_status

// Macros for testing the results of functions that return crunchy::Status or
// crunchy::StatusOr<T> (for any type T).
#define CRUNCHY_EXPECT_OK(expression) \
  EXPECT_THAT(expression, ::testing::crunchy_status::IsOk())
#define CRUNCHY_ASSERT_OK(expression) \
  ASSERT_THAT(expression, ::testing::crunchy_status::IsOk())
#define CRUNCHY_CHECK_OK(expression) \
  CRUNCHY_CHECK_EQ(expression, crunchy::OkStatus())

// Returns a gMock matcher that matches a StatusOr<> whose status is
// OK and whose value matches the inner matcher.
template <typename InnerMatcher>
internal_crunchy_status::IsOkAndHoldsMatcher<
    typename std::decay<InnerMatcher>::type>
IsOkAndHolds(InnerMatcher&& inner_matcher) {
  return internal_crunchy_status::IsOkAndHoldsMatcher<
      typename std::decay<InnerMatcher>::type>(
      std::forward<InnerMatcher>(inner_matcher));
}

// Returns a gMock matcher that matches a Status or StatusOr<>  whose status
// code matches code_matcher, and whose error message matches message_matcher.
template <typename StatusCodeMatcher>
internal_crunchy_status::StatusIsMatcher StatusIs(
    StatusCodeMatcher&& code_matcher, Matcher<const std::string&> message_matcher) {
  return internal_crunchy_status::StatusIsMatcher(
      std::forward<StatusCodeMatcher>(code_matcher),
      std::move(message_matcher));
}

// Returns a gMock matcher that matches a Status or StatusOr<> whose status code
// matches code_matcher.
template <typename StatusCodeMatcher>
internal_crunchy_status::StatusIsMatcher StatusIs(
    StatusCodeMatcher&& code_matcher) {
  return StatusIs(std::forward<StatusCodeMatcher>(code_matcher), _);
}

// Returns a gMock matcher that matches a Status or StatusOr<> which is OK.
inline internal_crunchy_status::IsOkMatcher IsOk() {
  return internal_crunchy_status::IsOkMatcher();
}

}  // namespace crunchy_status
}  // namespace testing

#endif  // CRUNCHY_INTERNAL_COMMON_STATUS_MATCHERS_H_
