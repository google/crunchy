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

# Symmetric encryption primitives

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "crypter_interface",
    hdrs = ["crypter_interface.h"],
    deps = [
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "crypter_base",
    srcs = ["crypter_base.cc"],
    hdrs = ["crypter_base.h"],
    deps = [
        ":crypter_interface",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "crypter_test",
    testonly = 1,
    srcs = ["crypter_test.cc"],
    hdrs = ["crypter_test.h"],
    deps = [
        ":crypter_interface",
        "//crunchy/internal/algs/crypt/testdata:crypter_test_vectors_proto_cc",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "aes_gcm",
    srcs = ["aes_gcm.cc"],
    hdrs = ["aes_gcm.h"],
    deps = [
        ":crypter_base",
        ":crypter_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aes_gcm_test",
    srcs = ["aes_gcm_test.cc"],
    data = ["//crunchy/internal/algs/crypt/testdata"],
    deps = [
        ":aes_gcm",
        ":crypter_interface",
        ":crypter_test",
        "//crunchy/internal/algs/crypt/testdata:crypter_test_vectors_proto_cc",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "aes_eax",
    srcs = ["aes_eax.cc"],
    hdrs = ["aes_eax.h"],
    deps = [
        ":crypter_base",
        ":crypter_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aes_eax_test",
    srcs = ["aes_eax_test.cc"],
    data = ["//crunchy/internal/algs/crypt/testdata"],
    deps = [
        ":aes_eax",
        ":crypter_test",
        "//crunchy/internal/algs/crypt/testdata:crypter_test_vectors_proto_cc",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)
