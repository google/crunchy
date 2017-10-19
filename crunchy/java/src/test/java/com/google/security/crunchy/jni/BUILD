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

# Tests for jni Bindings

package(
    default_visibility = ["//crunchy/java:internal_pkg"],
)

licenses(["notice"])  # Apache 2.0

java_test(
    name = "CrunchyCrypterBindingsTest",
    size = "small",
    srcs = ["CrunchyCrypterBindingsTest.java"],
    data = ["//crunchy/internal/keyset/testdata"],
    test_class = "com.google.security.crunchy.jni.CrunchyCrypterBindingsTest",
    deps = [
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_java_lite",
        "//crunchy/java/src/main/java/com/google/security/crunchy",
        "//crunchy/java/src/main/java/com/google/security/crunchy/jni",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)

java_test(
    name = "CrunchyMacerBindingsTest",
    size = "small",
    srcs = ["CrunchyMacerBindingsTest.java"],
    data = ["//crunchy/internal/keyset/testdata"],
    test_class = "com.google.security.crunchy.jni.CrunchyMacerBindingsTest",
    deps = [
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_java_lite",
        "//crunchy/java/src/main/java/com/google/security/crunchy",
        "//crunchy/java/src/main/java/com/google/security/crunchy/jni",
        "//crunchy/java/third_party:junit",
    ],
)

java_test(
    name = "CrunchyHybridCrypterBindingsTest",
    size = "small",
    srcs = ["CrunchyHybridCrypterBindingsTest.java"],
    data = ["//crunchy/internal/keyset/testdata"],
    test_class = "com.google.security.crunchy.jni.CrunchyHybridCrypterBindingsTest",
    deps = [
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_java_lite",
        "//crunchy/java/src/main/java/com/google/security/crunchy",
        "//crunchy/java/src/main/java/com/google/security/crunchy/jni",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)

java_test(
    name = "CrunchySignerBindingsTest",
    size = "small",
    srcs = ["CrunchySignerBindingsTest.java"],
    data = ["//crunchy/internal/keyset/testdata"],
    test_class = "com.google.security.crunchy.jni.CrunchySignerBindingsTest",
    deps = [
        "//crunchy/internal/keyset/testdata:factory_test_vectors_proto_java_lite",
        "//crunchy/java/src/main/java/com/google/security/crunchy",
        "//crunchy/java/src/main/java/com/google/security/crunchy/jni",
        "//crunchy/java/third_party:junit",
    ],
)
