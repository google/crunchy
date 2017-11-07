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

# Internal APIs for individual keys in a keyset.

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//crunchy/internal/common:proto.bzl", "crunchy_proto_library")

cc_library(
    name = "aead_crypting_key",
    srcs = ["aead_crypting_key.cc"],
    hdrs = ["aead_crypting_key.h"],
    deps = [
        "//crunchy/internal/algs/crypt:crypter_interface",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aead_crypting_key_test",
    srcs = ["aead_crypting_key_test.cc"],
    data = ["//crunchy/internal/keys/testdata"],
    deps = [
        ":aead_crypting_key",
        ":aead_crypting_key_test_vectors_proto_cc",
        "//crunchy/internal/algs/crypt:openssl_aead",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "@com_google_googletest//:gtest",
    ],
)

crunchy_proto_library(
    name = "aead_crypting_key_test_vectors_proto",
    testonly = 1,
    srcs = ["aead_crypting_key_test_vectors.proto"],
    deps = ["//crunchy/key_management/internal:keyset_proto"],
)

cc_test(
    name = "signing_key_test",
    srcs = ["signing_key_test.cc"],
    data = ["//crunchy/internal/keys/testdata"],
    deps = [
        ":signing_key",
        ":signing_key_test_vectors_proto_cc",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/algs/sign:ed25519",
        "//crunchy/internal/algs/sign:p256_ecdsa",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "signing_key",
    srcs = ["signing_key.cc"],
    hdrs = ["signing_key.h"],
    deps = [
        "//crunchy/internal/algs/sign:signer_interface",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

crunchy_proto_library(
    name = "signing_key_test_vectors_proto",
    testonly = 1,
    srcs = ["signing_key_test_vectors.proto"],
    deps = ["//crunchy/key_management/internal:keyset_proto"],
)

cc_library(
    name = "macing_key",
    srcs = ["macing_key.cc"],
    hdrs = ["macing_key.h"],
    deps = [
        "//crunchy/internal/algs/mac:mac_interface",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "macing_key_test",
    srcs = ["macing_key_test.cc"],
    data = ["//crunchy/internal/keys/testdata"],
    deps = [
        ":macing_key",
        ":macing_key_test_vectors_proto_cc",
        "//crunchy/internal/algs/mac:openssl_hmac",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "@com_google_googletest//:gtest",
    ],
)

crunchy_proto_library(
    name = "macing_key_test_vectors_proto",
    testonly = 1,
    srcs = ["macing_key_test_vectors.proto"],
    deps = ["//crunchy/key_management/internal:keyset_proto"],
)

cc_library(
    name = "hybrid_crypting_key",
    srcs = ["hybrid_crypting_key.cc"],
    hdrs = ["hybrid_crypting_key.h"],
    deps = [
        "//crunchy/internal/algs/hybrid",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "hybrid_crypting_key_test",
    srcs = ["hybrid_crypting_key_test.cc"],
    data = ["//crunchy/internal/keys/testdata"],
    deps = [
        ":hybrid_crypting_key",
        ":hybrid_crypting_key_test_vectors_proto_cc",
        "//crunchy/internal/algs/hybrid",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "@com_google_googletest//:gtest",
    ],
)

crunchy_proto_library(
    name = "hybrid_crypting_key_test_vectors_proto",
    testonly = 1,
    srcs = ["hybrid_crypting_key_test_vectors.proto"],
    deps = ["//crunchy/key_management/internal:keyset_proto"],
)

cc_library(
    name = "key_util",
    hdrs = ["key_util.h"],
    deps = [
        "//crunchy/key_management:key_handle",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "key_util_test",
    srcs = ["key_util_test.cc"],
    deps = [
        ":key_util",
        "//crunchy/key_management:keyset_enums_proto_cc",
        "//crunchy/key_management/internal:advanced_keyset_manager",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "@com_google_googletest//:gtest_main",
    ],
)
