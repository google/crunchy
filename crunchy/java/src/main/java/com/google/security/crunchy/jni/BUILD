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

# jni-based implementations of crunchy crypto

package(
    default_visibility = ["//crunchy/java:internal_pkg"],
)

licenses(["unencumbered"])  # Owned by Google

java_library(
    name = "jni",
    srcs = [
        "CrunchyCrypterBindings.java",
        "CrunchyHybridDecrypterBindings.java",
        "CrunchyHybridEncrypterBindings.java",
        "CrunchyMacerBindings.java",
        "CrunchySignerBindings.java",
        "CrunchyVerifierBindings.java",
    ],
    deps = [
        ":init_jni",
        "//crunchy/java/src/main/java/com/google/security/crunchy",
        "//crunchy/java/third_party:guava",
    ],
)

cc_library(
    name = "crypto_bindings",
    srcs = [
        "crypto.c",
        "crypto.h",
    ],
    deps = [
        ":jni_deps",
        "//crunchy/internal/bindings:crypto",
        "//crunchy/internal/pure_c:crypto",
    ],
    alwayslink = 1,
)

cc_binary(
    name = "libcrypto_jni.so",
    linkshared = 1,
    deps = [":crypto_bindings"],
)

java_library(
    name = "init_jni",
    srcs = [
        "InitJni.java",
    ],
    data = [":libcrypto_jni.so"],
)

# Cribbed from bazel //src/main/native/BUILD.oss
genrule(
    name = "copy_link_jni_md_header",
    srcs = ["@local_jdk//:jni_md_header-linux"],
    outs = ["jni_md.h"],
    cmd = "cp -f $< $@",
)

genrule(
    name = "copy_link_jni_header",
    srcs = ["@local_jdk//:jni_header"],
    outs = ["jni.h"],
    cmd = "cp -f $< $@",
)

cc_library(
    name = "jni_deps",
    srcs = [
        ":jni.h",
        ":jni_md.h",
    ],
    includes = ["."],
)
