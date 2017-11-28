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

# Hybrid encryption primitives.

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "hybrid",
    srcs = ["hybrid.cc"],
    hdrs = ["hybrid.h"],
    deps = [
        ":dem",
        ":kem",
        ":openssl_kem",
        ":x25519_kem",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "hybrid_test",
    srcs = ["hybrid_test.cc"],
    data = ["//crunchy/internal/algs/hybrid/testdata"],
    deps = [
        ":hybrid",
        "//crunchy/internal/algs/hybrid/testdata:hybrid_test_vectors_proto_cc",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "kem",
    hdrs = ["kem.h"],
    deps = [
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "openssl_kem",
    srcs = ["openssl_kem.cc"],
    hdrs = ["openssl_kem.h"],
    deps = [
        ":kem",
        "//crunchy/internal/algs/kdf:hkdf",
        "//crunchy/internal/algs/openssl:ec",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "x25519_kem",
    srcs = ["x25519_kem.cc"],
    hdrs = ["x25519_kem.h"],
    deps = [
        ":kem",
        "//crunchy/internal/algs/kdf:hkdf",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/algs/openssl:openssl_unique_ptr",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "openssl_kem_test",
    srcs = ["openssl_kem_test.cc"],
    data = ["//crunchy/internal/algs/hybrid/testdata"],
    deps = [
        ":openssl_kem",
        ":x25519_kem",
        "//crunchy/internal/algs/hybrid/testdata:hybrid_test_vectors_proto_cc",
        "//crunchy/internal/algs/kdf:hkdf",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)

cc_library(
    name = "dem",
    srcs = ["dem.cc"],
    hdrs = ["dem.h"],
    deps = [
        "//crunchy/internal/algs/crypt:crypter_interface",
        "//crunchy/internal/algs/crypt:openssl_aead",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/util:status",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "dem_test",
    srcs = ["dem_test.cc"],
    deps = [
        ":dem",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "@com_google_googletest//:gtest_main",
    ],
)
