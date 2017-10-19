#include "crunchy/internal/algs/hash/sha384.h"

#include <gtest/gtest.h>
#include "absl/strings/escaping.h"
#include "crunchy/internal/common/status_matchers.h"
#include "crunchy/util/status.h"

namespace crunchy {

namespace {

void TestOneVector(absl::string_view message,
                   absl::string_view expected_digest) {
  auto status_or = Sha384Hash(message);
  CRUNCHY_EXPECT_OK(status_or);
  EXPECT_EQ(status_or.ValueOrDie(), absl::HexStringToBytes(expected_digest));
}

TEST(Sha384Test, TestVectors) {
  // From: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
  TestOneVector("abc",
                "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5B"
                "ED8086072BA1E7CC2358BAECA134C825A7");
  TestOneVector(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
      "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A"
      "557E2DB966C3E9FA91746039");
}

}  // namespace

}  // namespace crunchy
