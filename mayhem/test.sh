#!/usr/bin/env bash
# mayhem/test.sh — runs ng's hermetic unit suite (built by build.sh, normal flags).
# Each test binary asserts known-answer values (RFC 9001 Appendix A QUIC keys,
# HPACK/frame encodings, CLI parsing results, request bytes) and prints
# "<suite>: all checks passed" only when every check held; a case passes only
# with exit 0 AND that line. `slowhttptest-ng -h` must print its usage text.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

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

B=ng/build-tests
[ -x "$B/slowhttptest-ng" ] || { echo "FATAL: $B not built — run mayhem/build.sh" >&2; exit 2; }
passed=0; failed=0
for t in slow_headers slow_read slow_body expect_continue slow_tls quic slow_quic \
         range cli report http2 h2_attacks reactor; do
  bin="$B/test_$t"
  if [ ! -x "$bin" ]; then echo "FAIL $t (missing)"; failed=$((failed+1)); continue; fi
  out=$(timeout 120 "$bin" 2>&1); rc=$?
  if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q 'all checks passed'; then
    echo "PASS $t"; passed=$((passed+1))
  else
    printf '%s\n' "$out" | tail -20; echo "FAIL $t (rc=$rc)"; failed=$((failed+1))
  fi
done
out=$("$B/slowhttptest-ng" -h 2>&1); rc=$?
if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -qi 'usage'; then
  echo "PASS cli_help"; passed=$((passed+1))
else echo "FAIL cli_help"; failed=$((failed+1)); fi
emit_ctrf "slowhttp-unit" "$passed" "$failed" 0
