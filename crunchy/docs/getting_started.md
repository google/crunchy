# CrunchyCrypt - Getting Started

CrunchyCrypt is an opensource cryptographic library offering safe and
easy-to-use APIs with a built-in key-versioning protocol.

This guide describes how to build/run the examples provided.

## Table of Contents

-   [Dependencies](#dependencies)
-   [Building/Running Examples](#exampes)

Contact us at crunchy-discuss@googlegroups.com
([link](https://groups.google.com/forum/#!forum/crunchy-discuss))

<a name="dependencies"></a>

## Dependencies

CrunchyCrypt uses [Bazel](https://www.bazel.build/) to manage and install
dependencies. ([How to Install
Bazel](https://docs.bazel.build/versions/master/install.html))

The complete list of dependencies required by CrunchyCrypt are listed in the
provided WORKSPACE file. For example, CrunchyCrypt depends on
[BoringSSL](https://boringssl.googlesource.com/boringssl/) and
[Abseil](https://github.com/abseil/abseil-cpp).

<a name="examples"></a>

## Building/Running Examples

Examples are provides in the examples/ directory of the CrunchyCrypt source
tree. [Bazel](https://www.bazel.build/) will automatically download/installl all
dependencies, compile all source files and run the code provided in the examples
by issuing the `bazel run` command.

The authenticated ecryption example, which encrypts/decrypts a plaintext using
AES-128 in GCM mode, can be run by executing `bazel run examples:aead`. A
successful execution will result in a `PASSED` output similar to the following.

```shell
crunchy/$ bazel run examples:aead

INFO: Analysed target //crunchy/examples:aead (0 packages loaded).
INFO: Found 1 target...
Target //crunchy/examples:aead up-to-date:
  bazel-bin/crunchy/examples/aead
INFO: Elapsed time: 0.284s, Critical Path: 0.01s
INFO: Build completed successfully, 1 total action

INFO: Running command line: bazel-bin/crunchy/examples/aead
[==========] Running 1 test from 1 test case.
[----------] Global test environment set-up.
[----------] 1 test from Aes128GcmEncryptionExample
[ RUN      ] Aes128GcmEncryptionExample.Run
[       OK ] Aes128GcmEncryptionExample.Run (0 ms)
[----------] 1 test from Aes128GcmEncryptionExample (0 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test case ran. (0 ms total)
[  PASSED  ] 1 test.
```
