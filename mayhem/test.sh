#!/usr/bin/env bash
#
# mayhem/test.sh — RUN libva-utils' upstream gtest suite (test_va_api), built by build.sh.
#
# libva-utils' unit/functional suite is a single gtest binary (test_va_api). All but one of its
# test cases are VAAPI-fixture tests that call vaInitialize() against a real GPU/VAAPI driver, which
# is unavailable in a headless CI/commit container — so we RUN the hardware-independent cases
# (the `Internal.*` group, which asserts real behavior of the project's Resolution logic) and count
# the driver-bound cases as SKIPPED (recorded, with reason). This is the project's own suite, not an
# invented oracle. Output is mapped to a CTRF summary.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

BIN=/mayhem/test_va_api
if [ ! -x "$BIN" ]; then
  echo "ERROR: $BIN missing — build.sh must build the gtest suite first" >&2
  # fall through to emit a failing CTRF
fi

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$BIN" ]; then
  emit_ctrf "gtest-test_va_api" 0 1 0
  exit $?
fi

# Total upstream test cases (for the skipped accounting). gtest_list_tests prints a suite line
# (ends with '.') followed by indented test names.
TOTAL=$("$BIN" --gtest_list_tests 2>/dev/null | grep -cE '^  [A-Za-z]' || true)
[ -n "$TOTAL" ] || TOTAL=0

XML=/tmp/gtest_internal.xml
rm -f "$XML"
"$BIN" --gtest_filter='Internal.*' --gtest_output="xml:$XML" >/tmp/gtest_internal.log 2>&1
GRC=$?
cat /tmp/gtest_internal.log

read -r RUN FAIL <<<"$(python3 - "$XML" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    r = ET.parse(sys.argv[1]).getroot()
    tests = int(r.get("tests", 0))
    failures = int(r.get("failures", 0)) + int(r.get("errors", 0))
except Exception:
    tests, failures = 0, 0
print(tests, failures)
PY
)"
RUN=${RUN:-0}; FAIL=${FAIL:-0}

# If the binary produced no results at all (e.g. it was neutered / crashed before running),
# that is a hard failure of the oracle.
if [ "$RUN" -eq 0 ]; then
  echo "ERROR: test_va_api ran 0 Internal tests (rc=$GRC)" >&2
  emit_ctrf "gtest-test_va_api" 0 1 0
  exit $?
fi

PASSED=$(( RUN - FAIL ))
SKIPPED=$(( TOTAL - RUN ))
[ "$SKIPPED" -lt 0 ] && SKIPPED=0

echo "test_va_api: ran $RUN Internal test(s), $FAIL failed; $SKIPPED VAAPI-driver test(s) skipped (no GPU/driver in container)"
emit_ctrf "gtest-test_va_api" "$PASSED" "$FAIL" "$SKIPPED"
exit $?
