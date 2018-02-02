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

# Tests for signing

licenses(["notice"])  # Apache 2.0

java_test(
    name = "P256EcdsaSignerFactoryTest",
    size = "small",
    srcs = ["P256EcdsaSignerFactoryTest.java"],
    data = ["//crunchy/internal/algs/sign/testdata"],
    test_class = "com.google.security.crunchy.algs.sign.P256EcdsaSignerFactoryTest",
    deps = [
        "//crunchy/internal/algs/sign/testdata:sign_test_vectors_proto_java_lite",
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/algs/sign:p256_ecdsa_signer_factory",
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/algs/sign:subtle_signer",
        "//crunchy/java/src/test/java/com/google/security/crunchy/internal/common:hex",
        "//crunchy/java/third_party:junit",
        "//crunchy/java/third_party:truth",
    ],
)
