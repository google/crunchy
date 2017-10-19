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

# Cryptographic MAC implementations.

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

cc_library(
    name = "mac_interface",
    hdrs = ["mac_interface.h"],
    deps = [
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "openssl_hmac",
    srcs = ["openssl_hmac.cc"],
    hdrs = ["openssl_hmac.h"],
    deps = [
        ":mac_interface",
        "//crunchy/internal/algs/openssl:errors",
        "//crunchy/internal/common:string_buffer",
        "//crunchy/util:status",
        "@boringssl//:crypto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "openssl_hmac_test",
    srcs = ["openssl_hmac_test.cc"],
    data = ["//crunchy/internal/algs/mac/testdata"],
    deps = [
        ":openssl_hmac",
        "//crunchy/internal/algs/mac/testdata:mac_test_vectors_proto_cc",
        "//crunchy/internal/algs/random:crypto_rand",
        "//crunchy/internal/common:init",
        "//crunchy/internal/common:status_matchers",
        "//crunchy/internal/common:test_factory",
        "//crunchy/internal/port",
        "//crunchy/util:status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest",
    ],
)
