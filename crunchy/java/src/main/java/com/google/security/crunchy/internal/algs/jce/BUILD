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

# Jce helper functions

package(
    default_visibility = ["//crunchy/java:internal_pkg"],
)

licenses(["notice"])  # Apache 2.0

java_library(
    name = "p256",
    srcs = ["P256.java"],
    deps = [
        "//crunchy/java/src/main/java/com/google/security/crunchy/internal/common:big_integer_util",
        "//crunchy/java/third_party:guava",
    ],
)
