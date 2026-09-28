#!/usr/bin/env bash
set -euo pipefail

# Build a static-analysis-only ReSukiSU LKM candidate for the TCL T653T01
# V655/V665/V667 family.  This script never connects to a TV and never loads
# the resulting module.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
LAB="${TCL_LAB:-/media/mint/Local IA/TCL_C855_Firmware_Lab}"
PACKAGE_NAME="${KSU_PACKAGE_NAME:-com.philiphall6.resukisu.tcl}"
CERTIFICATE="${TCL_RELEASE_CERTIFICATE:-/home/mint/.android/tcl-v643-v1-release.der}"
SOURCE_REF="${TCL_RESUKISU_REF:-HEAD}"
SOURCE_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$SOURCE_REF")"
SOURCE_SHORT="$(git -C "$REPO_ROOT" rev-parse --short=12 "$SOURCE_COMMIT")"

TARGET_RELEASE='5.15.192-android14-11'
TARGET_SUBLEVEL='192'
PUBLISHED_KERNEL_RELEASE='5.15.180-android14-11'
KERNEL_COMMIT='b16d79aec7e6099adaa99d0504cea36d1c1801c7'

BUILD_ROOT="${TCL_V65X_BUILD_ROOT:-/home/mint/tcl-v65x-resukisu-$SOURCE_SHORT}"
RSRC="$BUILD_ROOT/resukisu-src"
PUBLISHED_KERNEL_ROOT="${TCL_KERNEL_BUILD_ROOT:-/home/mint/tcl-v643-resukisu-exact-20260922}"
KSRC="$PUBLISHED_KERNEL_ROOT/kernel-src"
BASE_KOUT="$PUBLISHED_KERNEL_ROOT/kernel-out"
KOUT="$BUILD_ROOT/kernel-out-$TARGET_RELEASE"
TOOLCHAIN="${TCL_TOOLCHAIN:-/home/mint/android-clang-r487747c/bin}"
DIST="${TCL_V65X_LKM_OUT_DIR:-$REPO_ROOT/dist-tcl/v65x-analysis/module}"
LOGS="$DIST/logs"

ANALYSIS="$LAB/11_KERNEL_ANALYSIS_GENERATED/V655_V665_V667_20260927"
COMPARE_TOOL="$LAB/09_TOOLS/compare_resukisu_tcl_modversions.py"
BTF_COMPARE_TOOL="$LAB/09_TOOLS/compare_btf_layouts.py"
VERIFY_TOOL="$REPO_ROOT/scripts/verify-tcl-v65x-lkm-analysis.py"
CLANG_WRAPPER_SOURCE="$LAB/09_TOOLS/clang_tcl_v643_wrapper.sh"
CLANG_COMPAT_WRAPPER_SOURCE="$LAB/09_TOOLS/clang_tcl_v643_compat_wrapper.sh"

for path in \
    "$CERTIFICATE" "$KSRC/Makefile" "$BASE_KOUT/.config" \
    "$BASE_KOUT/Module.symvers" "$COMPARE_TOOL" "$BTF_COMPARE_TOOL" \
    "$VERIFY_TOOL" \
    "$CLANG_WRAPPER_SOURCE" "$CLANG_COMPAT_WRAPPER_SOURCE" \
    "$ANALYSIS/V655-exact.btf" "$ANALYSIS/V665-exact.btf" \
    "$ANALYSIS/V667-exact.btf"; do
    [[ -f "$path" ]] || { echo "Missing required file: $path" >&2; exit 2; }
done

[[ "$(git -C "$KSRC" rev-parse HEAD)" == "$KERNEL_COMMIT" ]] || {
    echo "Unexpected published TCL kernel source commit" >&2
    exit 3
}

published_release="$(<"$BASE_KOUT/include/config/kernel.release")"
[[ "$published_release" == "$PUBLISHED_KERNEL_RELEASE" ]] || {
    echo "Unexpected published kernel release: $published_release" >&2
    exit 4
}

btf_hash="$(sha256sum "$ANALYSIS/V655-exact.btf" | awk '{print $1}')"
for version in 665 667; do
    candidate_hash="$(sha256sum "$ANALYSIS/V${version}-exact.btf" | awk '{print $1}')"
    [[ "$candidate_hash" == "$btf_hash" ]] || {
        echo "V${version} BTF differs from V655" >&2
        exit 5
    }
done

cert_size="$(stat -c '%s' "$CERTIFICATE")"
cert_hash="$(sha256sum "$CERTIFICATE" | awk '{print $1}')"
if (( cert_size > 1024 )); then
    echo "Certificate is too large for the KernelSU parser: $cert_size > 1024" >&2
    exit 6
fi

mkdir -p "$BUILD_ROOT" "$DIST" "$LOGS"
if [[ ! -e "$RSRC/.git" ]]; then
    git -C "$REPO_ROOT" worktree add --detach "$RSRC" "$SOURCE_COMMIT"
fi
[[ "$(git -C "$RSRC" rev-parse HEAD)" == "$SOURCE_COMMIT" ]] || {
    echo "Existing ReSukiSU worktree points to another commit" >&2
    exit 7
}

install -m 0755 "$CLANG_WRAPPER_SOURCE" "$BUILD_ROOT/clang"
install -m 0755 "$CLANG_COMPAT_WRAPPER_SOURCE" "$BUILD_ROOT/clang-compat"

if [[ ! -f "$KOUT/.config" ]]; then
    cp -a "$BASE_KOUT" "$KOUT"
fi

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
    SUBLEVEL="$TARGET_SUBLEVEL"
    CC="$BUILD_ROOT/clang"
    CC_COMPAT="$BUILD_ROOT/clang-compat"
)

# Regenerate UTS_RELEASE in the isolated output directory.  The published TCL
# source tree and the known-good V643 output directory remain untouched.
make "${MAKE_ARGS[@]}" prepare modules_prepare -j"$(nproc)" \
    2>&1 | tee "$LOGS/kernel-prepare.log"

release="$(make -s "${MAKE_ARGS[@]}" kernelrelease)"
[[ "$release" == "$TARGET_RELEASE" ]] || {
    echo "Unexpected generated kernel release: $release" >&2
    exit 8
}
grep -Fqx "$TARGET_RELEASE" "$KOUT/include/config/kernel.release"
grep -Fqx "#define UTS_RELEASE \"$TARGET_RELEASE\"" \
    "$KOUT/include/generated/utsrelease.h"

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

grep -Fq "Custom KernelSU Manager signature size: $cert_size" \
    "$LOGS/module-build.log"
grep -Fq "Custom KernelSU Manager signature hash: $cert_hash" \
    "$LOGS/module-build.log"
grep -Fq "KernelSU Manager package name: $PACKAGE_NAME" \
    "$LOGS/module-build.log"

module="$RSRC/kernel/kernelsu.ko"
full="$DIST/resukisu-tcl-v65x-$TARGET_RELEASE.ko"
stripped="$DIST/resukisu-tcl-v65x-$TARGET_RELEASE-stripped.ko"
install -m 0644 "$module" "$full"
install -m 0644 "$module" "$stripped"
llvm-strip --strip-debug "$stripped"

modinfo "$stripped" | tee "$DIST/MODINFO.txt"
grep -Fq "vermagic:       $TARGET_RELEASE SMP preempt mod_unload modversions aarch64" \
    "$DIST/MODINFO.txt"
grep -aFq "$PACKAGE_NAME" "$stripped"
grep -aFq "$cert_hash" "$stripped"

llvm-nm -u --format=posix "$stripped" | LC_ALL=C sort \
    > "$DIST/module-undefined-symbols.txt"

for version in 655 665 667; do
    vmlinux="$ANALYSIS/vmlinux-V${version}.elf"
    system_map="$ANALYSIS/System.map-V${version}.txt"
    [[ -f "$vmlinux" && -f "$system_map" ]] || {
        echo "Missing reconstructed V${version} kernel artifacts" >&2
        exit 9
    }
    python3 "$COMPARE_TOOL" \
        --module "$stripped" \
        --vmlinux "$vmlinux" \
        --system-map "$system_map" \
        --csv "$DIST/modversions-vs-V${version}.csv" \
        2>&1 | tee "$LOGS/modversions-V${version}.log"
done

python3 "$VERIFY_TOOL" \
    --module "$stripped" \
    --system-map "$ANALYSIS/System.map-V655.txt" \
    --system-map "$ANALYSIS/System.map-V665.txt" \
    --system-map "$ANALYSIS/System.map-V667.txt" \
    --symvers "$BASE_KOUT/Module.symvers" \
    --expected-release "$TARGET_RELEASE" \
    --expected-manager-package "$PACKAGE_NAME" \
    --expected-cert-hash "$cert_hash" \
    --report "$DIST/STATIC_VALIDATION_V65X.md" \
    2>&1 | tee "$LOGS/static-validation-V65x.log"

pahole \
    --btf_encode_detached="$DIST/resukisu-tcl-v65x-module-dwarf.btf" \
    --skip_encoding_btf_decl_tag \
    --skip_encoding_btf_type_tag \
    --skip_encoding_btf_vars \
    --skip_encoding_btf_inconsistent_proto \
    "$full"
python3 "$BTF_COMPARE_TOOL" \
    --module-btf "$DIST/resukisu-tcl-v65x-module-dwarf.btf" \
    --target-btf "$ANALYSIS/V655-exact.btf" \
    --report "$DIST/BTF_LAYOUT_VALIDATION_V655.md" \
    2>&1 | tee "$LOGS/btf-V655.log"

{
    printf 'analysis_only=true\n'
    printf 'load_authorized=false\n'
    printf 'source_commit=%s\n' "$SOURCE_COMMIT"
    printf 'published_kernel_commit=%s\n' "$KERNEL_COMMIT"
    printf 'published_kernel_release=%s\n' "$PUBLISHED_KERNEL_RELEASE"
    printf 'target_kernel_release=%s\n' "$TARGET_RELEASE"
    printf 'target_btf_sha256=%s\n' "$btf_hash"
    printf 'manager_package=%s\n' "$PACKAGE_NAME"
    printf 'certificate_size=%s\n' "$cert_size"
    printf 'certificate_sha256=%s\n' "$cert_hash"
} | tee "$DIST/BUILD-IDENTITY.txt"

cat > "$DIST/ANALYSIS_ONLY.txt" <<'EOF'
STATIC ANALYSIS CANDIDATE ONLY

The TCL 5.15.192 vendor source has not been published.  This module was built
from TCL's published 5.15.180 source/header baseline after generating an
isolated 5.15.192 UTS release.  Target BTF layouts and all imported symbol CRCs
match V655, V665 and V667, but that does not prove runtime safety.

Do not load this module on a TV until the GhostLock/reclaim route and cleanup
path have been validated independently for the exact firmware.
EOF

sha256sum "$full" "$stripped" \
    "$DIST/resukisu-tcl-v65x-module-dwarf.btf" \
    | tee "$DIST/SHA256SUMS-module"

echo "V65X_ANALYSIS_BUILD_OK=$stripped"
echo 'LOAD_AUTHORIZED=false'
