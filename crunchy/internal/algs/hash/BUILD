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

# Hashing

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "hash_interface",
    hdrs = ["hash_interface.h"],
    deps = [
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "sha256",
    srcs = ["sha256.cc"],
    hdrs = ["sha256.h"],
    deps = [
        ":hash_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "sha256_test",
    srcs = ["sha256_test.cc"],
    deps = [
        ":sha256",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "identity",
    srcs = ["identity.cc"],
    hdrs = ["identity.h"],
    deps = [
        ":hash_interface",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "identity_test",
    srcs = ["identity_test.cc"],
    deps = [
        ":identity",
        "//crunchy/internal/common:status_matchers",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "sha384",
    srcs = ["sha384.cc"],
    hdrs = ["sha384.h"],
    deps = [
        ":hash_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "sha384_test",
    srcs = ["sha384_test.cc"],
    deps = [
        ":sha384",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "sha512",
    srcs = ["sha512.cc"],
    hdrs = ["sha512.h"],
    deps = [
        ":hash_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "sha512_test",
    srcs = ["sha512_test.cc"],
    deps = [
        ":sha512",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)
