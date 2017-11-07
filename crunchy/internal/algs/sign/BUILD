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

# Sign contains libraries for asymmetric crypto signature generation and
# verification.

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "signer_interface",
    hdrs = ["signer_interface.h"],
    deps = [
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "signer_test",
    testonly = 1,
    hdrs = ["signer_test.h"],
    data = ["//crunchy/internal/algs/sign/testdata"],
    deps = [
        ":signer_interface",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/algs/sign/testdata:sign_test_vectors_proto_cc",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "rsa",
    srcs = ["rsa.cc"],
    hdrs = ["rsa.h"],
    deps = [
        ":signer_interface",
        "//crunchy/internal/algs/hash:hash_interface",
        "//crunchy/internal/algs/hash:sha256",
        "//crunchy/internal/algs/hash:sha384",
        "//crunchy/internal/algs/hash:sha512",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/common:pool",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "rsa_test",
    srcs = ["rsa_test.cc"],
    deps = [
        ":rsa",
        ":signer_interface",
        ":signer_test",
        "//crunchy/internal/algs/hash:sha256",
        "//crunchy/internal/algs/sign/testdata:sign_test_vectors_proto_cc",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "p256_ecdsa",
    srcs = ["p256_ecdsa.cc"],
    hdrs = ["p256_ecdsa.h"],
    deps = [
        ":ecdsa",
        ":signer_interface",
        "//crunchy/internal/algs/hash:sha256",
    ],
)

cc_library(
    name = "ecdsa",
    srcs = ["ecdsa.cc"],
    hdrs = ["ecdsa.h"],
    deps = [
        ":signer_interface",
        "//crunchy/internal/algs/hash:hash_interface",
        "//crunchy/internal/algs/openssl:ec",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "ecdsa_test",
    srcs = ["ecdsa_test.cc"],
    deps = [
        ":ecdsa",
        ":ecdsa_format",
        "//crunchy/internal/algs/hash:hash_interface",
        "//crunchy/internal/algs/hash:sha256",
        "//crunchy/internal/algs/hash:sha384",
        "//crunchy/internal/algs/hash:sha512",
        "//crunchy/internal/algs/openssl:ec",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ed25519",
    srcs = ["ed25519.cc"],
    hdrs = ["ed25519.h"],
    deps = [
        ":signer_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "ed25519_test",
    srcs = ["ed25519_test.cc"],
    deps = [
        ":ed25519",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "ecdsa_common_test",
    srcs = ["ecdsa_common_test.cc"],
    deps = [
        ":ecdsa",
        ":ed25519",
        ":p256_ecdsa",
        ":signer_interface",
        ":signer_test",
        "//crunchy/internal/algs/hash:identity",
        "//crunchy/internal/algs/hash:sha256",
        "//crunchy/internal/algs/hash:sha384",
        "//crunchy/internal/algs/hash:sha512",
        "//crunchy/internal/algs/sign/testdata:sign_test_vectors_proto_cc",
        "//crunchy/internal/common:flags",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "ecdsa_format_test",
    srcs = ["ecdsa_format_test.cc"],
    deps = [
        ":ecdsa_format",
        "//crunchy/internal/common:status_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ecdsa_format",
    srcs = ["ecdsa_format.cc"],
    hdrs = ["ecdsa_format.h"],
    deps = [
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/strings",
    ],
)
