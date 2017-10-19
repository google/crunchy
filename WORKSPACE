# GoogleTest/GoogleMock framework. Used by most unit-tests.
http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-master",
    urls = ["https://github.com/google/googletest/archive/master.zip"],
)

# Boringssl
git_repository(
    name = "boringssl",
    commit = "b8a5219531146b0907a72da8e62f331bb0d673c5",
    remote = "https://boringssl.googlesource.com/boringssl",
)

# Absl
git_repository(
    name = "com_google_absl",
    commit = "2a62fbdedf64673f7c858bc6487bd15bcd2ca180",
    remote = "https://github.com/abseil/abseil-cpp.git",
)

# CCTZ (Time-zone framework).
# Used by @com_google_absl//absl/synchronization
http_archive(
    name = "com_googlesource_code_cctz",
    strip_prefix = "cctz-master",
    urls = ["https://github.com/google/cctz/archive/master.zip"],
)

# Using a protobuf version 3.4.1
http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.4.1",
    urls = ["https://github.com/google/protobuf/archive/v3.4.1.zip"],
)

http_archive(
    name = "com_google_protobuf_cc",
    strip_prefix = "protobuf-3.4.1",
    urls = ["https://github.com/google/protobuf/archive/v3.4.1.zip"],
)

# Using a protobuf javalite version that contains @com_google_protobuf_javalite//:javalite_toolchain
http_archive(
    name = "com_google_protobuf_javalite",
    strip_prefix = "protobuf-javalite",
    urls = ["https://github.com/google/protobuf/archive/javalite.zip"],
)

# Java
maven_jar(
    name = "com_google_guava",
    artifact = "com.google.guava:guava:21.0",
)

maven_jar(
    name = "junit_junit",
    artifact = "junit:junit:4.11",
    sha1 = "4e031bb61df09069aeb2bffb4019e7a5034a4ee0",
)

maven_jar(
    name = "com_google_truth_truth",
    artifact = "com.google.truth:truth:0.30",
    sha1 = "9d591b5a66eda81f0b88cf1c748ab8853d99b18b",
)
