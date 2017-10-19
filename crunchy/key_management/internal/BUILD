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

# Key management APIs

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//crunchy/internal/common:proto.bzl", "crunchy_proto_library")

crunchy_proto_library(
    name = "keyset_proto",
    srcs = ["keyset.proto"],
    deps = [
        "//crunchy/internal/port:any_proto",
        "//crunchy/key_management:keyset_enums_proto",
    ],
)

cc_library(
    name = "advanced_keyset_manager",
    srcs = [
        "advanced_keyset_manager.cc",
    ],
    hdrs = [
        "advanced_keyset_manager.h",
    ],
    deps = [
        ":keyset_proto_cc",
        "//crunchy/internal/keys:key_util",
        "//crunchy/internal/keyset:aead_crypting_key_registry",
        "//crunchy/internal/keyset:hybrid_crypting_key_registry",
        "//crunchy/internal/keyset:macing_key_registry",
        "//crunchy/internal/keyset:signing_key_registry",
        "//crunchy/key_management:key_handle",
        "//crunchy/key_management:keyset_enums_proto_cc",
        "//crunchy/key_management:keyset_handle",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "advanced_keyset_manager_test",
    srcs = [
        "advanced_keyset_manager_test.cc",
    ],
    deps = [
        ":advanced_keyset_manager",
        ":keyset_proto_cc",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/key_management:keyset_enums_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_googletest//:gtest_main",
    ],
)
