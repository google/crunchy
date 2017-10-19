# Copyright 2017 The CrunchyCrypt Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Common openssl helper utils

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "errors",
    srcs = ["errors.cc"],
    hdrs = ["errors.h"],
    deps = [
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "openssl_unique_ptr",
    srcs = ["openssl_unique_ptr.cc"],
    hdrs = ["openssl_unique_ptr.h"],
    deps = [
        "//crunchy/internal/port",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "openssl_unique_ptr_test",
    srcs = ["openssl_unique_ptr_test.cc"],
    deps = [
        ":openssl_unique_ptr",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ec",
    srcs = ["ec.cc"],
    hdrs = ["ec.h"],
    deps = [
        ":errors",
        ":openssl_unique_ptr",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "ec_test",
    srcs = ["ec_test.cc"],
    deps = [
        ":ec",
        "//crunchy/internal/common:status_matchers",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)
