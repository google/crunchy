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

# Common utility libraries

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "string_buffer",
    hdrs = ["string_buffer.h"],
    deps = [
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "test_factory",
    testonly = 1,
    srcs = ["test_factory.cc"],
    hdrs = ["test_factory.h"],
    deps = [
        ":file",
        ":init",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/port",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "pool",
    hdrs = ["pool.h"],
    deps = [
        "//crunchy/internal/port",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_library(
    name = "file",
    hdrs = ["file.h"],
    deps = [
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "init",
    testonly = 1,
    hdrs = ["init.h"],
)

cc_library(
    name = "status_matchers",
    testonly = 1,
    srcs = ["status_matchers.cc"],
    hdrs = ["status_matchers.h"],
    deps = [
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)
