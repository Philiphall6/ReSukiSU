#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PACKAGE_NAME="${KSU_PACKAGE_NAME:-com.philiphall6.resukisu.tcl}"
MANAGER_NAME="${KSU_NAME:-ReSukiSU TCL C855}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-/home/mint/Android/Sdk}"
ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK_ROOT/ndk/29.0.14206865}"
BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-$ANDROID_SDK_ROOT/build-tools/36.1.0}"
KEYSTORE="${TCL_RELEASE_KEYSTORE:-/home/mint/.android/tcl-v643-v1-release.jks}"
CERTIFICATE="${TCL_RELEASE_CERTIFICATE:-/home/mint/.android/tcl-v643-v1-release.der}"
KEY_ALIAS="${TCL_RELEASE_KEY_ALIAS:-tcl-v643-v1-release}"
PASSWORD_FILE="${TCL_RELEASE_PASSWORD_FILE:-/home/mint/.android/tcl-v643-release.pass}"
BUILD_LABEL="${TCL_BUILD_LABEL:-v1.0-candidate}"
OUT_DIR="${TCL_MANAGER_OUT_DIR:-$REPO_ROOT/dist-tcl/$BUILD_LABEL}"

for path in "$KEYSTORE" "$CERTIFICATE" "$BUILD_TOOLS/apksigner" "$BUILD_TOOLS/aapt2"; do
    [[ -f "$path" ]] || { echo "Missing required file: $path" >&2; exit 2; }
done

if [[ -z "${TCL_RELEASE_STORE_PASS:-}" ]]; then
    IFS= read -r TCL_RELEASE_STORE_PASS < "$PASSWORD_FILE"
fi
TCL_RELEASE_KEY_PASS="${TCL_RELEASE_KEY_PASS:-$TCL_RELEASE_STORE_PASS}"
export TCL_RELEASE_STORE_PASS TCL_RELEASE_KEY_PASS
export ANDROID_HOME="$ANDROID_SDK_ROOT"
export ANDROID_SDK_ROOT ANDROID_NDK_HOME
export LIBCLANG_PATH="${LIBCLANG_PATH:-$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/lib}"
export CARGO_TARGET_DIR="$REPO_ROOT/target"
export KSU_PACKAGE_NAME="$PACKAGE_NAME"

cert_size="$(stat -c '%s' "$CERTIFICATE")"
cert_hash="$(sha256sum "$CERTIFICATE" | awk '{print $1}')"
if (( cert_size > 1024 )); then
    echo "Certificate is too large for the KernelSU parser: $cert_size > 1024" >&2
    exit 3
fi

mkdir -p "$OUT_DIR"

(
    cd "$REPO_ROOT/userspace/ksud"
    cargo +nightly ndk b -P 26 -t armv7-linux-androideabi -r
    cargo +nightly ndk b -P 26 -t aarch64-linux-android -r
)

(
    cd "$REPO_ROOT/manager"
    ./gradlew :app:assembleRelease \
        -PKSU_PACKAGE_NAME="$PACKAGE_NAME" \
        -PKSU_NAME="$MANAGER_NAME"
)

input_apk="$(find "$REPO_ROOT/manager/app/build/outputs/apk/release" \
    -maxdepth 1 -type f -name '*universal-release.apk' -print | LC_ALL=C sort | tail -n 1)"
[[ -n "$input_apk" && -f "$input_apk" ]] || {
    echo "Universal release APK was not produced" >&2
    exit 4
}

python3 "$REPO_ROOT/repack_apk.py" repack \
    --apk "$input_apk" \
    --ksud-build-type release \
    --arch armeabi-v7a \
    --arch arm64-v8a \
    --strip \
    --keystore-path "$KEYSTORE" \
    --key-alias "$KEY_ALIAS" \
    --keystore-pass env:TCL_RELEASE_STORE_PASS \
    --key-pass env:TCL_RELEASE_KEY_PASS \
    --output-name "ReSukiSU-TCL-T653T01-V643-$BUILD_LABEL" \
    --out-dir "$OUT_DIR"

apk="$OUT_DIR/ReSukiSU-TCL-T653T01-V643-$BUILD_LABEL.apk"
"$BUILD_TOOLS/apksigner" verify --verbose --print-certs "$apk" \
    | tee "$OUT_DIR/APKSIGNER-VERIFY.txt"
"$BUILD_TOOLS/aapt2" dump badging "$apk" \
    | tee "$OUT_DIR/AAPT2-BADGING.txt"

apk_cert_hash="$(awk -F': ' '/certificate SHA-256 digest/{print tolower($2); exit}' \
    "$OUT_DIR/APKSIGNER-VERIFY.txt")"
[[ "$apk_cert_hash" == "$cert_hash" ]] || {
    echo "APK certificate mismatch: $apk_cert_hash != $cert_hash" >&2
    exit 5
}
grep -Fq "package: name='$PACKAGE_NAME'" "$OUT_DIR/AAPT2-BADGING.txt" || {
    echo "Unexpected APK package name" >&2
    exit 6
}
python3 - "$apk" "$PACKAGE_NAME" <<'PY'
import sys
from zipfile import ZipFile

apk, package = sys.argv[1], sys.argv[2].encode("ascii")
with ZipFile(apk) as archive:
    for arch in ("armeabi-v7a", "arm64-v8a"):
        path = f"lib/{arch}/libksud.so"
        if package not in archive.read(path):
            raise SystemExit(f"{arch} ksud does not contain the dedicated package identity")
PY

{
    printf 'package=%s\n' "$PACKAGE_NAME"
    printf 'manager_name=%s\n' "$MANAGER_NAME"
    printf 'certificate_size=%s\n' "$cert_size"
    printf 'certificate_sha256=%s\n' "$cert_hash"
    printf 'source_commit=%s\n' "$(git -C "$REPO_ROOT" rev-parse HEAD)"
} | tee "$OUT_DIR/BUILD-IDENTITY.txt"

sha256sum "$apk" \
    "$REPO_ROOT/target/armv7-linux-androideabi/release/ksud" \
    "$REPO_ROOT/target/aarch64-linux-android/release/ksud" \
    | tee "$OUT_DIR/SHA256SUMS-manager"

echo "MANAGER_BUILD_OK=$apk"
