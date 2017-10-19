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

# Implementations of crunchy crypto objects.

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "aead_crypting_key_registry",
    srcs = ["aead_crypting_key_registry.cc"],
    hdrs = ["aead_crypting_key_registry.h"],
    deps = [
        "//crunchy/internal/algs/crypt:aes_eax",
        "//crunchy/internal/algs/crypt:aes_gcm",
        "//crunchy/internal/keys:aead_crypting_key",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "aead_crypting_key_registry_test",
    srcs = ["aead_crypting_key_registry_test.cc"],
    deps = [
        ":aead_crypting_key_registry",
        "//crunchy/internal/algs/crypt:aes_gcm",
        "//crunchy/internal/common:status_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "crypter_factory",
    srcs = ["crypter_factory.cc"],
    hdrs = ["crypter_factory.h"],
    deps = [
        ":aead_crypting_key_registry",
        ":keyset_util",
        "//crunchy:crunchy_crypter",
        "//crunchy/internal/keys:aead_crypting_key",
        "//crunchy/internal/port",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "crypter_factory_test",
    srcs = ["crypter_factory_test.cc"],
    data = ["//crunchy/internal/keyset/testdata"],
    deps = [
        ":crypter_factory",
        ":keyset_util",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/keys:key_util",
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_cc",
        "//crunchy/key_management:crunchy_factory",
        "//crunchy/key_management:key_handle",
        "//crunchy/key_management:keyset_manager",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "signing_key_registry",
    srcs = ["signing_key_registry.cc"],
    hdrs = ["signing_key_registry.h"],
    deps = [
        "//crunchy/internal/algs/sign:ed25519",
        "//crunchy/internal/algs/sign:p256_ecdsa",
        "//crunchy/internal/algs/sign:rsa",
        "//crunchy/internal/keys:signing_key",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "signing_key_registry_test",
    srcs = ["signing_key_registry_test.cc"],
    deps = [
        ":signing_key_registry",
        "//crunchy/internal/algs/sign:p256_ecdsa",
        "//crunchy/internal/common:status_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "signer_factory",
    srcs = ["signer_factory.cc"],
    hdrs = ["signer_factory.h"],
    deps = [
        ":keyset_util",
        ":signing_key_registry",
        "//crunchy:crunchy_signer",
        "//crunchy/internal/keys:signing_key",
        "//crunchy/internal/port",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "signer_factory_test",
    srcs = ["signer_factory_test.cc"],
    data = ["//crunchy/internal/keyset/testdata"],
    deps = [
        ":keyset_util",
        ":signer_factory",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/keys:key_util",
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_cc",
        "//crunchy/key_management:crunchy_factory",
        "//crunchy/key_management:key_handle",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management:keyset_manager",
        "//crunchy/key_management/internal:advanced_keyset_manager",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "macing_key_registry",
    srcs = ["macing_key_registry.cc"],
    hdrs = ["macing_key_registry.h"],
    deps = [
        "//crunchy/internal/algs/mac:openssl_hmac",
        "//crunchy/internal/keys:macing_key",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "macing_key_registry_test",
    srcs = ["macing_key_registry_test.cc"],
    deps = [
        ":macing_key_registry",
        "//crunchy/internal/algs/mac:openssl_hmac",
        "//crunchy/internal/common:status_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "macer_factory",
    srcs = ["macer_factory.cc"],
    hdrs = ["macer_factory.h"],
    deps = [
        ":keyset_util",
        ":macing_key_registry",
        "//crunchy:crunchy_macer",
        "//crunchy/internal/keys:macing_key",
        "//crunchy/internal/port",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management:keyset_manager",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "macer_factory_test",
    srcs = ["macer_factory_test.cc"],
    data = ["//crunchy/internal/keyset/testdata"],
    deps = [
        ":keyset_util",
        ":macer_factory",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/keys:key_util",
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_cc",
        "//crunchy/key_management:crunchy_factory",
        "//crunchy/key_management:key_handle",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management:keyset_manager",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "hybrid_crypting_key_registry",
    srcs = ["hybrid_crypting_key_registry.cc"],
    hdrs = ["hybrid_crypting_key_registry.h"],
    deps = [
        "//crunchy/internal/algs/hybrid",
        "//crunchy/internal/keys:hybrid_crypting_key",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "hybrid_crypting_key_registry_test",
    srcs = ["hybrid_crypting_key_registry_test.cc"],
    deps = [
        ":hybrid_crypting_key_registry",
        "//crunchy/internal/algs/hybrid",
        "//crunchy/internal/common:status_matchers",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "hybrid_crypter_factory",
    srcs = ["hybrid_crypter_factory.cc"],
    hdrs = ["hybrid_crypter_factory.h"],
    deps = [
        ":hybrid_crypting_key_registry",
        ":keyset_util",
        "//crunchy:crunchy_hybrid_crypter",
        "//crunchy/internal/keys:hybrid_crypting_key",
        "//crunchy/internal/port",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "hybrid_crypter_factory_test",
    srcs = ["hybrid_crypter_factory_test.cc"],
    data = ["//crunchy/internal/keyset/testdata"],
    deps = [
        ":hybrid_crypter_factory",
        ":keyset_util",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/keys:key_util",
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_cc",
        "//crunchy/key_management:crunchy_factory",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management:keyset_manager",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "keyset_util",
    hdrs = ["keyset_util.h"],
    deps = [
        "//crunchy/internal/keys:key_util",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_test(
    name = "keyset_util_test",
    srcs = ["keyset_util_test.cc"],
    deps = [
        ":keyset_util",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/key_management:keyset_enums_proto_cc",
        "//crunchy/key_management:keyset_manager",
        "//crunchy/key_management/internal:advanced_keyset_manager",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_googletest//:gtest_main",
    ],
)
