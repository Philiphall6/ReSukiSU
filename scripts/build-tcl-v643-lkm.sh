#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LAB="${TCL_LAB:-/media/mint/Local IA/TCL_C855_Firmware_Lab}"
PACKAGE_NAME="${KSU_PACKAGE_NAME:-com.philiphall6.resukisu.tcl}"
CERTIFICATE="${TCL_RELEASE_CERTIFICATE:-/home/mint/.android/tcl-v643-v1-release.der}"
SOURCE_REF="${TCL_RESUKISU_REF:-HEAD}"
SOURCE_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$SOURCE_REF")"
SOURCE_SHORT="$(git -C "$REPO_ROOT" rev-parse --short=12 "$SOURCE_COMMIT")"
BUILD_LABEL="${TCL_BUILD_LABEL:-v1.0-candidate}"
BUILD_ROOT="${TCL_LKM_BUILD_ROOT:-/home/mint/tcl-v643-resukisu-$SOURCE_SHORT}"
RSRC="$BUILD_ROOT/resukisu-src"
KERNEL_ROOT="${TCL_KERNEL_BUILD_ROOT:-/home/mint/tcl-v643-resukisu-exact-20260922}"
KSRC="$KERNEL_ROOT/kernel-src"
KOUT="$KERNEL_ROOT/kernel-out"
TOOLCHAIN="${TCL_TOOLCHAIN:-/home/mint/android-clang-r487747c/bin}"
DIST="${TCL_LKM_OUT_DIR:-$REPO_ROOT/dist-tcl/$BUILD_LABEL/module}"
LOGS="$DIST/logs"

KERNEL_COMMIT='b16d79aec7e6099adaa99d0504cea36d1c1801c7'
VMLINUX="$LAB/11_KERNEL_ANALYSIS_GENERATED/V643_20260918/output/vmlinux-v643.elf"
SYSTEM_MAP="$LAB/11_KERNEL_ANALYSIS_GENERATED/V643_20260918/output/System.map-v643.txt"
V643_BTF="$LAB/11_KERNEL_ANALYSIS_GENERATED/V643_20260918/metadata/v643-exact.btf"
COMPARE_TOOL="$LAB/09_TOOLS/compare_resukisu_tcl_modversions.py"
VERIFY_TOOL="$LAB/09_TOOLS/verify_resukisu_tcl_v643_bundle.py"
BTF_COMPARE_TOOL="$LAB/09_TOOLS/compare_btf_layouts.py"
CLANG_WRAPPER_SOURCE="$LAB/09_TOOLS/clang_tcl_v643_wrapper.sh"
CLANG_COMPAT_WRAPPER_SOURCE="$LAB/09_TOOLS/clang_tcl_v643_compat_wrapper.sh"

for path in "$CERTIFICATE" "$VMLINUX" "$SYSTEM_MAP" "$V643_BTF" \
    "$KOUT/.config" "$KOUT/Module.symvers" "$COMPARE_TOOL" "$VERIFY_TOOL" \
    "$BTF_COMPARE_TOOL" "$CLANG_WRAPPER_SOURCE" "$CLANG_COMPAT_WRAPPER_SOURCE"; do
    [[ -f "$path" ]] || { echo "Missing required file: $path" >&2; exit 2; }
done
[[ "$(git -C "$KSRC" rev-parse HEAD)" == "$KERNEL_COMMIT" ]] || {
    echo "Unexpected TCL kernel source commit" >&2
    exit 3
}

cert_size="$(stat -c '%s' "$CERTIFICATE")"
cert_hash="$(sha256sum "$CERTIFICATE" | awk '{print $1}')"
if (( cert_size > 1024 )); then
    echo "Certificate is too large for the KernelSU parser: $cert_size > 1024" >&2
    exit 4
fi

mkdir -p "$BUILD_ROOT" "$DIST" "$LOGS"
if [[ ! -e "$RSRC/.git" ]]; then
    git -C "$REPO_ROOT" worktree add --detach "$RSRC" "$SOURCE_COMMIT"
fi
[[ "$(git -C "$RSRC" rev-parse HEAD)" == "$SOURCE_COMMIT" ]] || {
    echo "Existing ReSukiSU build worktree points to another commit" >&2
    exit 5
}

install -m 0755 "$CLANG_WRAPPER_SOURCE" "$BUILD_ROOT/clang"
install -m 0755 "$CLANG_COMPAT_WRAPPER_SOURCE" "$BUILD_ROOT/clang-compat"

export PATH="$TOOLCHAIN:$PATH"
export ARCH=arm64
export LLVM=1
export LLVM_IAS=1
export KBUILD_BUILD_USER=build-user
export KBUILD_BUILD_HOST=build-host
export KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP='Wed Nov 12 18:27:20 UTC 2025'

MAKE_ARGS=(
    -C "$KSRC"
    O="$KOUT"
    ARCH=arm64
    LLVM=1
    LLVM_IAS=1
    CC="$BUILD_ROOT/clang"
    CC_COMPAT="$BUILD_ROOT/clang-compat"
)

release="$(make -s "${MAKE_ARGS[@]}" kernelrelease)"
[[ "$release" == '5.15.180-android14-11' ]] || {
    echo "Unexpected kernel release: $release" >&2
    exit 6
}

make "${MAKE_ARGS[@]}" M="$RSRC/kernel" clean
make "${MAKE_ARGS[@]}" \
    M="$RSRC/kernel" \
    CONFIG_KSU=m \
    CONFIG_KSU_TRACEPOINT_HOOK=y \
    CONFIG_KSU_MULTI_MANAGER_SUPPORT=y \
    KSU_EXPECTED_SIZE="$cert_size" \
    KSU_EXPECTED_HASH="$cert_hash" \
    KSU_MANAGER_PACKAGE="$PACKAGE_NAME" \
    KCFLAGS="-I$KOUT/security/selinux" \
    KBUILD_MODPOST_WARN=1 \
    -j"$(nproc)" modules 2>&1 | tee "$LOGS/module-build.log"

grep -Fq "Custom KernelSU Manager signature size: $cert_size" "$LOGS/module-build.log"
grep -Fq "Custom KernelSU Manager signature hash: $cert_hash" "$LOGS/module-build.log"
grep -Fq "KernelSU Manager package name: $PACKAGE_NAME" "$LOGS/module-build.log"

module="$RSRC/kernel/kernelsu.ko"
full="$DIST/resukisu-tcl-v643-5.15.180-android14-11.ko"
stripped="$DIST/resukisu-tcl-v643-5.15.180-android14-11-stripped.ko"
install -m 0644 "$module" "$full"
install -m 0644 "$module" "$stripped"
llvm-strip --strip-debug "$stripped"

modinfo "$stripped" | tee "$DIST/MODINFO.txt"
grep -Fq 'vermagic:       5.15.180-android14-11 SMP preempt mod_unload modversions aarch64' \
    "$DIST/MODINFO.txt"
grep -aFq "$PACKAGE_NAME" "$stripped"
grep -aFq "$cert_hash" "$stripped"

python3 "$COMPARE_TOOL" \
    --module "$stripped" \
    --vmlinux "$VMLINUX" \
    --system-map "$SYSTEM_MAP" \
    --csv "$DIST/modversions-vs-v643.csv" \
    2>&1 | tee "$LOGS/modversions-validation.log"
if awk -F, 'NR > 1 && $4 != "MATCH" {bad=1} END {exit bad}' \
    "$DIST/modversions-vs-v643.csv"; then :; else
    echo "Module CRC mismatch against V643" >&2
    exit 7
fi

llvm-nm -u --format=posix "$stripped" | LC_ALL=C sort \
    > "$DIST/module-undefined-symbols.txt"
pahole \
    --btf_encode_detached="$DIST/resukisu-tcl-v643-module-dwarf.btf" \
    --skip_encoding_btf_decl_tag \
    --skip_encoding_btf_type_tag \
    --skip_encoding_btf_vars \
    --skip_encoding_btf_inconsistent_proto \
    "$full"
python3 "$BTF_COMPARE_TOOL" \
    --module-btf "$DIST/resukisu-tcl-v643-module-dwarf.btf" \
    --target-btf "$V643_BTF" \
    --report "$DIST/BTF_LAYOUT_VALIDATION.md" \
    2>&1 | tee "$LOGS/btf-layout-validation.log"

ksud32="$REPO_ROOT/target/armv7-linux-androideabi/release/ksud"
ksud64="$REPO_ROOT/target/aarch64-linux-android/release/ksud"
[[ -f "$ksud32" && -f "$ksud64" ]] || {
    echo "Build the manager/ksud bundle first" >&2
    exit 8
}
install -m 0644 "$ksud32" "$DIST/ksud-armv7"
install -m 0644 "$ksud64" "$DIST/ksud-arm64"
python3 "$VERIFY_TOOL" \
    --bundle "$DIST" \
    --module "$stripped" \
    --ksud32 "$DIST/ksud-armv7" \
    --ksud64 "$DIST/ksud-arm64" \
    --expected-manager-package "$PACKAGE_NAME" \
    --expected-cert-hash "$cert_hash" \
    --report "$DIST/STATIC_VALIDATION.md" \
    2>&1 | tee "$LOGS/static-validation.log"

{
    printf 'source_commit=%s\n' "$SOURCE_COMMIT"
    printf 'kernel_commit=%s\n' "$KERNEL_COMMIT"
    printf 'kernel_release=%s\n' "$release"
    printf 'manager_package=%s\n' "$PACKAGE_NAME"
    printf 'certificate_size=%s\n' "$cert_size"
    printf 'certificate_sha256=%s\n' "$cert_hash"
} | tee "$DIST/BUILD-IDENTITY.txt"
sha256sum "$full" "$stripped" "$DIST/ksud-armv7" "$DIST/ksud-arm64" \
    | tee "$DIST/SHA256SUMS-module"

echo "LKM_BUILD_OK=$stripped"
