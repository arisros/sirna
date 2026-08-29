#!/usr/bin/env bash
# Cross-target conformance for the Kotlin bindings, on a desktop JVM.
#
# No Android SDK, no NDK, no emulator, no device — which is the point. The
# Android client's agreement with the format is provable before any of the ten
# gigabytes of Android tooling exists anywhere, and before a line of app code
# is written.
set -euo pipefail

cd "$(dirname "$0")/../.."
TARGET="${CARGO_TARGET_DIR:-target}"
OUT="${TARGET}/sirna-jvm"
BINDINGS="android/bindings"
JNA="${JNA_JAR:-/home/opt/jars/jna.jar}"

command -v kotlinc >/dev/null || { echo "kotlinc not on PATH"; exit 1; }
[ -f "$JNA" ] || { echo "JNA jar not found at $JNA (set JNA_JAR)"; exit 1; }

# The DEBUG artifact, deliberately. The release profile sets `strip = true`,
# which removes the metadata symbols uniffi-bindgen reads — the failure is
# silent, and the only symptom is "Crate sirna_ffi not found in <the library
# that plainly contains it>".
cargo build -p sirna-ffi
LIB="${TARGET}/debug"

mkdir -p "$OUT"
rm -rf "$BINDINGS" && mkdir -p "$BINDINGS"
cargo run --release -p sirna-ffi --bin uniffi-bindgen -- \
  generate --library --language kotlin --out-dir "$BINDINGS" "$LIB/libsirna_ffi.so"

kotlinc -cp "$JNA" \
  "$BINDINGS"/uniffi/sirna_ffi/sirna_ffi.kt android/tests-jvm/Vectors.kt \
  -include-runtime -d "$OUT/vectors.jar"

# jna.library.path, not java.library.path — JNA does its own lookup.
java -cp "$OUT/vectors.jar:$JNA" \
  -Djna.library.path="$LIB" \
  -Dsirna.vectors="$PWD/spec/vectors" \
  VectorsKt
