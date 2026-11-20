#!/usr/bin/env bash
# mayhem/build.sh — builds the ng library (sanitized) + four libFuzzer harnesses
# and their -standalone reproducers, and the ng unit-test suite with normal flags.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:?base image must provide STANDALONE_FUZZ_MAIN}"
export CC CXX
cd "$SRC"

OUT="$SRC/mayhem/out"
mkdir -p "$OUT"

# 1) The ng engine library (static libslowhttp.a), instrumented, TLS on (QUIC
#    packet building needs OpenSSL). Only the library target: the e2e/test
#    executables are built separately below with normal flags.
FUZZ_CXXFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
cmake -S ng -B ng/build-fuzz -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="$FUZZ_CXXFLAGS" -DCMAKE_CXX_FLAGS_DEBUG="-O1"
cmake --build ng/build-fuzz -j"$MAYHEM_JOBS" --target slowhttp

# 2) Harnesses. fuzz_url also pulls in the classic tree's URL parser.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
$CXX $FUZZ_CXXFLAGS -O1 -c src/slowurl.cc -o "$OUT/slowurl.o"
# Classic tree: its generated config.h comes from an out-of-tree configure
# (under the gitignored mayhem/out/), then the sources are compiled with the
# fuzz flags; main() is renamed so the harness can call the real CLI.
CL="$OUT/classic"
mkdir -p "$CL"
[ -f "$CL/config.h" ] || (cd "$CL" && "$SRC/configure" >/dev/null)
CLASSIC_OBJS=""
for f in slowhttptest slowsocket slowstats slowlog text-generator range-generator; do
  $CXX $FUZZ_CXXFLAGS -O1 -DHAVE_CONFIG_H -I"$CL" -Isrc -c "src/$f.cc" -o "$CL/$f.o"
  CLASSIC_OBJS="$CLASSIC_OBJS $CL/$f.o"
done
$CXX $FUZZ_CXXFLAGS -O1 -DHAVE_CONFIG_H -I"$CL" -Isrc -Dmain=slowhttptest_main \
     -c src/slowhttptestmain.cc -o "$CL/slowhttptestmain.o"
CLASSIC_OBJS="$CLASSIC_OBJS $CL/slowhttptestmain.o $OUT/slowurl.o"

LIBS="ng/build-fuzz/libslowhttp.a -lssl -lcrypto -pthread"
for h in fuzz_ng_cli fuzz_ng_reply fuzz_ng_quic fuzz_url fuzz_classic_cli; do
  extra=""
  [ "$h" = fuzz_url ] && extra="$OUT/slowurl.o"
  [ "$h" = fuzz_classic_cli ] && extra="$CLASSIC_OBJS"
  $CXX -std=c++17 $FUZZ_CXXFLAGS -O1 -DSLOWHTTP_HAVE_TLS -Ing/include -Isrc -Imayhem/harnesses \
       -c "mayhem/harnesses/$h.cpp" -o "$OUT/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$h.o" $extra "$OUT/lsan_off.o" \
       $LIBS -o "/mayhem/$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$h.o" $extra "$OUT/lsan_off.o" \
       $LIBS -o "/mayhem/$h-standalone"
done

# 3) ng unit tests with the project's normal flags (Release), for test.sh.
cmake -S ng -B ng/build-tests -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build ng/build-tests -j"$MAYHEM_JOBS"
