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

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//crunchy/internal/common:proto.bzl", "crunchy_proto_library")

cc_library(
    name = "crypto_rand",
    srcs = ["crypto_rand.cc"],
    hdrs = ["crypto_rand.h"],
    deps = [
        "//crunchy/internal/port:logging",
        "@boringssl//:crypto",
    ],
)

cc_test(
    name = "crypto_rand_test",
    srcs = ["crypto_rand_test.cc"],
    deps = [
        ":crypto_rand",
        "@com_google_googletest//:gtest_main",
    ],
)
