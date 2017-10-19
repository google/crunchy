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

# Test data for mac tests.
#
# The test data is post-fixed with .proto.bin and consists of
# binary-serialized protos of the types defined in mac_test_vectors.proto
# The protos are generated in the tests using the flag --gen_test_vectors

package(default_visibility = ["//crunchy:internal_pkg"])

licenses(["notice"])  # Apache 2.0

load("//crunchy/internal/common:proto.bzl", "crunchy_proto_library")

crunchy_proto_library(
    name = "mac_test_vectors_proto",
    testonly = 1,
    srcs = ["mac_test_vectors.proto"],
)

filegroup(
    name = "testdata",
    testonly = 1,
    srcs = glob(["*.proto.bin"]),
)
