#!/usr/bin/env bash
# Collect evidence from the real Gradle/Cargo Android build. This deliberately measures
# a forced second invocation of the exact game task: Gradle must run it, while Cargo
# should report a no-op/incremental hit for an unchanged workspace.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
REPORT="$ROOT/dist/native-build-diagnostics"
mkdir -p "$REPORT"

TASK=":app:buildHorizonGamearm64_v8a"
echo "Measuring unchanged-workspace Cargo rebuild via $TASK"
set +e
/usr/bin/time -f 'elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nmax_rss_kb=%M' \
  -o "$REPORT/noop-rebuild-time.txt" \
  gradle "$TASK" --rerun-tasks --no-daemon --console plain 2>&1 | tee "$REPORT/noop-rebuild.log"
STATUS=${PIPESTATUS[0]}
set -e
if [ "$STATUS" -ne 0 ]; then
  echo "No-op rebuild diagnostic failed with exit $STATUS" >&2
  exit "$STATUS"
fi

{
  echo "rustc: $(rustc --version --verbose | tr '\n' ' ')"
  echo "cargo: $(cargo --version)"
  echo "host: $(uname -a)"
  echo "target: aarch64-linux-android"
  echo "ndk: ${ANDROID_NDK_HOME:-unset}"
  if [ -n "${ANDROID_NDK_HOME:-}" ]; then
    "${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang" --version | head -1
  fi
  echo "upstream: $(tr -d '[:space:]' < android/.upstream-built)"
  echo "android_patch_sha256: $(sha256sum android/android.patch android/android-next.patch | sha256sum | cut -d' ' -f1)"
  echo "overlay_sha256: $(find android/overlay -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
} > "$REPORT/build-identity.txt"

cargo metadata --offline --format-version 1 --no-deps --manifest-path horizon/Cargo.toml > "$REPORT/horizon-metadata.json"
cargo tree --offline --manifest-path horizon/Cargo.toml -p horizon-android-game --target aarch64-linux-android > "$REPORT/horizon-android-game-dependency-tree.txt"

TARGET="$ROOT/app/build/rust-target"
find "$TARGET" -type f \( -name '*.rlib' -o -name '*.rmeta' -o -name '*.so' -o -name '*.a' \) \
  -printf '%s %p\n' | sort -nr > "$REPORT/cargo-artifacts.txt"
{
  echo "artifact_count=$(wc -l < "$REPORT/cargo-artifacts.txt")"
  awk '{ total += $1 } END { printf "artifact_bytes=%0.f\n", total }' "$REPORT/cargo-artifacts.txt"
  echo "target_dir_bytes=$(du -sb "$TARGET" | cut -f1)"
} > "$REPORT/cargo-artifact-summary.txt"

NDK_READelf="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
for lib in app/build/generated/jniLibs/arm64-v8a/libhorizon_core.so \
           app/build/generated/jniLibs/arm64-v8a/libhorizon_msa.so \
           app/build/generated/jniLibs/arm64-v8a/libhorizon_android_game.so; do
  [ -s "$lib" ] || continue
  name=$(basename "$lib")
  sha256sum "$lib" >> "$REPORT/native-library-sha256.txt"
  "$NDK_READelf" -h -d "$lib" > "$REPORT/$name.elf.txt"
  stat -c '%n %s bytes' "$lib" >> "$REPORT/native-library-sizes.txt"
done

find "$TARGET/cargo-timings" -maxdepth 1 -type f -name '*.html' -print 2>/dev/null \
  | sort > "$REPORT/cargo-timing-files.txt" || true

echo "Diagnostics written to $REPORT"
