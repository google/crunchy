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

#ifndef CRUNCHY_INTERNAL_COMMON_TEST_FACTORY_H_
#define CRUNCHY_INTERNAL_COMMON_TEST_FACTORY_H_

#include <stddef.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/message.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "crunchy/internal/algs/random/crypto_rand.h"
#include "crunchy/internal/common/file.h"
#include "crunchy/internal/common/init.h"
#include "crunchy/internal/port/port.h"

namespace crunchy {

// Helper function to generate random integers.
// Bias, but good enough for tests
inline size_t BiasRandInt(size_t sup) { return Rand64() % sup; }

// Holds a reference to a factory and the name of the factory
template <class F>
struct FactoryInfo {
  std::string name;
  const F& factory;
  std::string test_data_path;
};

template <class T>
StatusOr<T> GetProtoFromFile(absl::string_view filename) {
  static_assert(std::is_base_of<::google::protobuf::Message, T>::value,
                "Template type is not a subclass of ::google::protobuf::Message");
  if (filename.empty()) {
    return InvalidArgumentError("filename is empty.");
  }
  T proto;
  std::string serialized_test_vectors;
  Status status = GetFile(filename, &serialized_test_vectors);
  if (!status.ok()) {
    return FailedPreconditionErrorBuilder(CRUNCHY_LOC)
           << "Couldn't load file " << filename << ".";
  }
  if (!proto.ParseFromString(serialized_test_vectors)) {
    return FailedPreconditionError("Couldn't parse proto.");
  }
  return std::move(proto);
}

template <class T>
T GetProtoFromFileOrDie(absl::string_view filename) {
  StatusOr<T> status_or_proto = GetProtoFromFile<T>(filename);
  CRUNCHY_CHECK_OK(status_or_proto.status());
  return std::move(status_or_proto).ValueOrDie();
}

// See hybrid_test.cc for sample usage.
// Templated with a factory class F and an initializer I.
template <class F, std::vector<FactoryInfo<F>>* (*I)()>
class FactoryParamTest : public ::testing::TestWithParam<FactoryInfo<F>> {
 public:
  // Returns the name of a given factory as provided by the initializer.
  static std::string GetNameFromParam(testing::TestParamInfo<FactoryInfo<F>> param) {
    return param.param.name;
  }

  // Returns the FactoryInfo for a given name.
  static FactoryInfo<F> GetFactoryInfo(absl::string_view name) {
    for (auto item : factories()) {
      if (item.name == name) {
        return item;
      }
    }
    CRUNCHY_LOG(FATAL) << name << " not found";
  }

  // Generates and returns a static copy of the initializer I.
  static const std::vector<FactoryInfo<F>>& factories() {
    static const std::vector<FactoryInfo<F>>& factories = *I();
    return factories;
  }

  template <class T>
  static void SetTestVectors(absl::string_view name, const T& test_vectors) {
    CRUNCHY_EXPECT_OK(SetFile(GetFactoryInfo(name).test_data_path,
                              test_vectors.SerializeAsString()));
  }

 protected:
  const std::string& name() { return this->GetParam().name; }
  const F& factory() { return this->GetParam().factory; }
  const std::string& test_data_path() { return this->GetParam().test_data_path; }

  template <class T>
  T GetTestVectors() {
    EXPECT_FALSE(this->GetParam().test_data_path.empty());
    auto status_or_test_vectors =
        GetProtoFromFile<T>(this->GetParam().test_data_path);
    CRUNCHY_EXPECT_OK(status_or_test_vectors.status())
        << "Couldn't load test vectors, try passing --gen_test_vectors="
        << name();
    return std::move(status_or_test_vectors).ValueOrDie();
  }
};

}  // namespace crunchy

#endif  // CRUNCHY_INTERNAL_COMMON_TEST_FACTORY_H_
