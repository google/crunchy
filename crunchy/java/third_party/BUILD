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

"""Defines CruchyCrypt bazel dependencies."""

licenses(["notice"])  # Apache 2.0

package(
    default_visibility = ["//crunchy/java:internal_pkg"],
)

java_plugin(
    name = "auto_annotation_plugin",
    processor_class = "com.google.auto.value.processor.AutoAnnotationProcessor",
    deps = ["@com_google_auto//jar"],
)

java_plugin(
    name = "auto_value_plugin",
    processor_class = "com.google.auto.value.processor.AutoValueProcessor",
    deps = ["@com_google_auto//jar"],
)

java_library(
    name = "auto_value",
    exported_plugins = [
        ":auto_annotation_plugin",
        ":auto_value_plugin",
    ],
    exports = ["@com_google_auto//jar"],
)

java_library(
    name = "guava",
    exports = ["@com_google_guava//jar"],
)

java_library(
    name = "junit",
    exports = ["@junit_junit//jar"],
)

java_library(
    name = "truth",
    exports = [
        ":guava",
        "@com_google_truth_truth//jar",
    ],
)
