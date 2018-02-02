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

# Tests for common utility functions and testonly utility functions

package(
    default_visibility = ["//crunchy/java:internal_pkg"],
)

licenses(["notice"])  # Apache 2.0

java_library(
    name = "hex",
    testonly = 1,
    srcs = ["Hex.java"],
    deps = [
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/common:big_integer_util",
    ],
)

java_test(
    name = "BigIntegerUtilTest",
    size = "small",
    srcs = ["BigIntegerUtilTest.java"],
    test_class = "com.google.security.crunchy.internal.common.BigIntegerUtilTest",
    deps = [
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/common:big_integer_util",
        "//crunchy/java/third_party:guava",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)

java_test(
    name = "HexTest",
    size = "small",
    srcs = ["HexTest.java"],
    test_class = "com.google.security.crunchy.internal.common.HexTest",
    deps = [
        ":hex",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)

java_test(
    name = "ByteUtilTest",
    size = "small",
    srcs = ["ByteUtilTest.java"],
    test_class = "com.google.security.crunchy.internal.common.ByteUtilTest",
    deps = [
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/common:byte_util",
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/common:rand_util",
        "//crunchy/java/third_party:guava",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)

java_test(
    name = "RandUtilTest",
    size = "small",
    srcs = ["RandUtilTest.java"],
    test_class = "com.google.security.crunchy.internal.common.RandUtilTest",
    deps = [
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/common:rand_util",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)
