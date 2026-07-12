#!/usr/bin/env bash
#
# mayhem/build.sh — build libva-utils fuzz targets + the upstream gtest suite.
#
# Targets (names preserved from the fork's Mayhem history):
#   loadjpeg              — in-process libFuzzer harness over the loadjpeg CLI's pre-VAAPI
#                           decode path (see mayhem/fuzz_loadjpeg.cpp for the rationale).
#   tinyjpeg-parse-header — in-process libFuzzer harness over tinyjpeg_parse_header().
#
# Everything is built with $SANITIZER_FLAGS (ASan+UBSan, halting) + $DEBUG_FLAGS (DWARF<4)
# so the fuzzed code is instrumented. The gtest suite is built separately with normal flags
# for mayhem/test.sh.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

VA_CFLAGS="$(pkg-config --cflags libva)"
VA_LIBS="$(pkg-config --libs libva)"

meson_setup() {
  local dir="$1"; shift
  if [ -f "$dir/build.ninja" ]; then
    meson setup "$dir" --wipe "$@"
  else
    meson setup "$dir" "$@"
  fi
}

# ---------------------------------------------------------------------------
# 1) libFuzzer harnesses (+ standalone reproducers), one per Mayhem target.
#    Both link tinyjpeg.c (the parser) and va_display.c (referenced by tinyjpeg_decode).
# ---------------------------------------------------------------------------
SRCS="decode/tinyjpeg.c common/va_display.c"
INCS="-Idecode -Icommon $VA_CFLAGS"

# Standalone (non-fuzzer) run-once driver. Compile it as a C object first so its
# LLVMFuzzerTestOneInput reference keeps C linkage.
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o

for h in loadjpeg tinyjpeg_parse_header; do
  HARNESS=mayhem/fuzz_${h}.cpp
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    $HARNESS $SRCS $INCS $VA_LIBS \
    -o /mayhem/fuzz_${h}
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS \
    $HARNESS $SRCS /tmp/standalone_main.o $INCS $VA_LIBS \
    -o /mayhem/fuzz_${h}-standalone
done

# ---------------------------------------------------------------------------
# 2) Upstream gtest suite (test_va_api), NORMAL flags — mayhem/test.sh RUNS it.
#    gtest is vendored in test/gtest (no network).
# ---------------------------------------------------------------------------
meson_setup build-tests \
  --buildtype=release \
  -Dtests=true -Dx11=false -Dwayland=false -Ddrm=true \
  -Dc_args="$COVERAGE_FLAGS" \
  -Dcpp_args="$COVERAGE_FLAGS" \
  -Dc_link_args="$COVERAGE_FLAGS" \
  -Dcpp_link_args="$COVERAGE_FLAGS"
ninja -C build-tests -j"$MAYHEM_JOBS" test/test_va_api
cp build-tests/test/test_va_api /mayhem/test_va_api
