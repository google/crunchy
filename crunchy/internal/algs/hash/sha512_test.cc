#include "crunchy/internal/algs/hash/sha512.h"

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

void TestOneVector(absl::string_view message,
                   absl::string_view expected_digest) {
  auto status_or = Sha512Hash(message);
  CRUNCHY_EXPECT_OK(status_or);
  EXPECT_EQ(status_or.ValueOrDie(), absl::HexStringToBytes(expected_digest));
}

TEST(Sha512Test, TestVectors) {
  // From: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
  TestOneVector("abc",
                "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D3"
                "9A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54C"
                "A49F");
  TestOneVector(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
      "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E"
      "4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909");
}

}  // namespace

}  // namespace crunchy
