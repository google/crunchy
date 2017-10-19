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

"""Generates proto targets in various languages."""

def crunchy_proto_library(name, testonly = 0, srcs = [], deps = []):
  """Generates proto targets in various languages."""
  native.proto_library(
      name = name,
      testonly = testonly,
      srcs = srcs,
      deps = deps)
  native.cc_proto_library(
      name = name + "_cc",
      testonly = testonly,
      deps = [":" + name])
  native.java_lite_proto_library(
      name = name + "_java_lite",
      testonly = testonly,
      deps = [":" + name])
