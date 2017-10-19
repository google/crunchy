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

// API for capturing source-code location information.
// Based on http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2015/n4519.pdf.
//
// To define a function that has access to the source location of the
// callsite, define it with a parameter of type source_location. The caller
// can then invoke the function, passing CRUNCHY_LOC as the argument.
//
// If at all possible, make the source_location parameter be the function's
// last parameter. That way, when std::source_location is available,
// you will be able to switch to it, and give the parameter a default
// argument of std::source_location::current(). Users will then be able to
// omit that argument, and the default will automatically capture the location
// of the callsite.
//
// Once std::source_location is available, you will be able to migrate your
// code by updating the crunchy::source_location function parameter to take
// std::source_location::current as the default argument
// (crunchy::source_location will be implicitly convertible from
// std::source_location), and then go through and remove the trailing macro
// argument from all calls to the function. Once that's done, you can switch the
// parameter type from crunchy::source_location to std::source_location.

#ifndef CRUNCHY_INTERNAL_PORT_SOURCE_LOCATION_H_
#define CRUNCHY_INTERNAL_PORT_SOURCE_LOCATION_H_

#include <cstdint>

namespace crunchy {

// Class representing a specific location in the source code of a program.
// source_location is copyable.
class source_location {
 public:
  // Avoid this constructor; it populates the object with dummy values.
  constexpr source_location()
      : line_(0),
        file_name_(nullptr) {}

  // Wrapper to invoke the private constructor below. This should only be
  // used by the CRUNCHY_LOC macro, hence the name.
  static constexpr source_location DoNotInvokeDirectly(std::uint_least32_t line,
                                                       const char* file_name) {
    return source_location(line, file_name);
  }

  // The line number of the captured source location.
  constexpr std::uint_least32_t line() const { return line_; }

  // The file name of the captured source location.
  constexpr const char* file_name() const { return file_name_; }

  // column() and function_name() are omitted because we don't have a
  // way to support them.

 private:
  // Do not invoke this constructor directly. Instead, use the
  // CRUNCHY_LOC macro below.
  //
  // file_name must outlive all copies of the source_location
  // object, so in practice it should be a std::string literal.
  constexpr source_location(std::uint_least32_t line, const char* file_name)
      : line_(line),
        file_name_(file_name) {}

  // "unused" members are present to minimize future changes in the size of
  // this type.
  std::uint_least32_t line_;
  std::uint_least32_t unused_column_ = 0;
  const char* file_name_;
  const char* unused_function_name_ = nullptr;
};

}  // namespace crunchy

// If a function takes a source_location parameter, pass this as the argument.
#define CRUNCHY_LOC \
  ::crunchy::source_location::DoNotInvokeDirectly(__LINE__, __FILE__)

#endif  // CRUNCHY_INTERNAL_PORT_SOURCE_LOCATION_H_
