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

# Implementations of the pure-c API backed by c++ interfaces.

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "crypto",
    srcs = ["crypto.cc"],
    hdrs = ["crypto.h"],
    deps = [
        "//crunchy:crunchy_crypter",
        "//crunchy:crunchy_hybrid_crypter",
        "//crunchy:crunchy_macer",
        "//crunchy:crunchy_signer",
        "//crunchy/internal/pure_c:crypto",
        "//crunchy/key_management:crunchy_factory",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "crypto_test",
    srcs = ["crypto_test.cc"],
    data = ["//crunchy/internal/keyset/testdata"],
    deps = [
        ":crypto",
        "//crunchy/internal/common:file",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/internal/keyset:aead_crypting_key_registry",
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_cc",
        "//crunchy/internal/port",
        "//crunchy/key_management/internal:keyset_proto_cc",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)
