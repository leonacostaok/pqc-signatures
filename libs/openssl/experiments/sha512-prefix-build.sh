#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "usage: $0 BASELINE_SOURCE CANDIDATE_SOURCE" >&2
  exit 2
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BASELINE_SOURCE="$(cd "$1" && pwd)"
CANDIDATE_SOURCE="$(cd "$2" && pwd)"
BUILD="$ROOT/libs/openssl/build/sha512-prefix"
PIN=122db7eb076bf0625df87b91bcc2dccfaccc4900
[[ "$(git -C "$BASELINE_SOURCE" rev-parse HEAD)" == "$PIN" ]]
[[ "$(git -C "$CANDIDATE_SOURCE" rev-parse HEAD)" == "$PIN" ]]
git -C "$BASELINE_SOURCE" diff --quiet "$PIN"
if ! cmp -s <(git -C "$CANDIDATE_SOURCE" diff --binary "$PIN") "$HERE/sha512-prefix.patch"; then
  echo "Candidate tracked changes do not match the recorded patch" >&2
  exit 1
fi
git -C "$BASELINE_SOURCE" apply --check "$HERE/sha512-prefix.patch"
git -C "$CANDIDATE_SOURCE" apply --check --reverse "$HERE/sha512-prefix.patch"
if cmp -s "$BASELINE_SOURCE/crypto/slh_dsa/slh_hash.c" "$CANDIDATE_SOURCE/crypto/slh_dsa/slh_hash.c"; then
  echo "Baseline and candidate hash sources are identical" >&2
  exit 1
fi

target=()
if [[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]]; then
  target=(darwin64-arm64-cc)
fi
link=(-lpthread)
if [[ "$(uname -s)" == Linux ]]; then link+=(-ldl); fi
for variant in baseline candidate; do
  src="$BASELINE_SOURCE"
  if [[ "$variant" == candidate ]]; then src="$CANDIDATE_SOURCE"; fi
  obj="$BUILD/$variant"
  mkdir -p "$obj"
  (
    cd "$obj"
    perl "$src/Configure" "${target[@]}" no-shared > configure.log 2>&1
    make -j"${JOBS:-2}" build_sw > build.log 2>&1
  )
  "${CC:-cc}" -O2 -Wall -Wextra -Wno-unused-parameter \
    -I"$obj/include" -I"$src/include" -I"$src" \
    "$HERE/sha512-prefix-check.c" "$obj/libcrypto.a" "${link[@]}" -o "$obj/prefix-check"
  "${CC:-cc}" -O2 -Wall -Wextra -I"$obj/include" -I"$src/include" \
    "$HERE/sha512-prefix-driver.c" "$obj/libcrypto.a" "${link[@]}" -o "$obj/prefix-driver"
  if [[ "$variant" == baseline ]]; then
    "$obj/prefix-check" > "$obj/resource-correctness.log" 2>&1
    if "$obj/prefix-check" --require-cache > "$obj/resource-gate.log" 2>&1; then
      echo "Baseline unexpectedly passes the optimization gate" >&2
      exit 1
    fi
  else
    "${CC:-cc}" -fsyntax-only -DOPENSSL_NO_DEPRECATED \
      -I"$obj/include" -I"$src/include" -I"$src" \
      "$src/crypto/slh_dsa/slh_dsa_hash_ctx.c" > "$obj/no-deprecated.log" 2>&1
    "$obj/prefix-check" --require-cache > "$obj/resource-gate.log" 2>&1
    (cd "$obj" && make test TESTS=test_slh_dsa > slh-tests.log 2>&1)
  fi
done
if cmp -s "$BUILD/baseline/prefix-driver" "$BUILD/candidate/prefix-driver"; then
  echo "Baseline and candidate binaries are identical" >&2
  exit 1
fi
echo "Built and checked both variants in $BUILD"
