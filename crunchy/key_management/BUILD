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

# Public-facing APIs

package(default_visibility = ["//visibility:public"])

licenses(["notice"])  # Apache 2.0

load("//crunchy/internal/common:proto.bzl", "crunchy_proto_library")

crunchy_proto_library(
    name = "keyset_enums_proto",
    srcs = ["keyset_enums.proto"],
)

cc_library(
    name = "key_handle",
    hdrs = [
        "key_handle.h",
    ],
    deps = [
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
    ],
)

cc_library(
    name = "keyset_handle",
    srcs = [
        "keyset_handle.cc",
    ],
    hdrs = [
        "keyset_handle.h",
    ],
    deps = [
        ":key_handle",
        "//crunchy/internal/keys:key_util",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
    ],
)

cc_library(
    name = "keyset_manager",
    srcs = [
        "keyset_manager.cc",
    ],
    hdrs = [
        "keyset_manager.h",
    ],
    deps = [
        ":key_handle",
        ":keyset_enums_proto_cc",
        ":keyset_handle",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:advanced_keyset_manager",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "keyset_manager_test",
    srcs = [
        "keyset_manager_test.cc",
    ],
    deps = [
        ":keyset_manager",
        "//crunchy:crunchy_crypter",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/keys:key_util",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "keyset_serialization",
    srcs = [
        "keyset_serialization.cc",
    ],
    hdrs = [
        "keyset_serialization.h",
    ],
    deps = [
        ":keyset_handle",
        "//crunchy/internal/keyset:keyset_util",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "keyset_serialization_test",
    srcs = [
        "keyset_serialization_test.cc",
    ],
    deps = [
        ":keyset_manager",
        ":keyset_serialization",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/keys:key_util",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "crunchy_factory",
    srcs = [
        "crunchy_factory.cc",
    ],
    hdrs = [
        "crunchy_factory.h",
    ],
    deps = [
        ":keyset_handle",
        "//crunchy:crunchy_crypter",
        "//crunchy:crunchy_hybrid_crypter",
        "//crunchy:crunchy_macer",
        "//crunchy:crunchy_signer",
        "//crunchy/internal/keyset:aead_crypting_key_registry",
        "//crunchy/internal/keyset:crypter_factory",
        "//crunchy/internal/keyset:hybrid_crypter_factory",
        "//crunchy/internal/keyset:hybrid_crypting_key_registry",
        "//crunchy/internal/keyset:keyset_util",
        "//crunchy/internal/keyset:macer_factory",
        "//crunchy/internal/keyset:macing_key_registry",
        "//crunchy/internal/keyset:signer_factory",
        "//crunchy/internal/keyset:signing_key_registry",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
    ],
)
