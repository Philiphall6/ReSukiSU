#!/usr/bin/env python3
"""Fail-closed static checks for the TCL V65x ReSukiSU candidate."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from collections import Counter
from pathlib import Path


def run(*command: str) -> str:
    return subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def fail(message: str) -> None:
    raise SystemExit(f"STATIC_VALIDATION_FAILED: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True, type=Path)
    parser.add_argument("--system-map", required=True, action="append", type=Path)
    parser.add_argument("--symvers", required=True, type=Path)
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--expected-manager-package", required=True)
    parser.add_argument("--expected-cert-hash", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--readelf", default="llvm-readelf")
    args = parser.parse_args()

    for path in (args.module, args.symvers, *args.system_map):
        if not path.is_file():
            fail(f"missing file: {path}")

    modinfo_bin = shutil.which("modinfo") or "/sbin/modinfo"
    modinfo = run(modinfo_bin, str(args.module))
    fields = {}
    for line in modinfo.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    expected_vermagic = (
        f"{args.expected_release} SMP preempt mod_unload modversions aarch64"
    )
    if fields.get("vermagic") != expected_vermagic:
        fail(f"unexpected vermagic: {fields.get('vermagic')!r}")
    if fields.get("name") != "kernelsu":
        fail(f"unexpected module name: {fields.get('name')!r}")

    notes = run(args.readelf, "-n", "-p", ".comment", str(args.module))
    if "based on r487747c" not in notes or "clang version 17.0.2" not in notes:
        fail("expected TCL Android Clang r487747c marker is absent")
    if "aarch64 feature: PAC" not in notes or "aarch64 feature: BTI" in notes:
        fail("ARM64 properties differ from the TCL kernel baseline")

    undefined_output = run(args.nm, "-u", "--format=posix", str(args.module))
    undefined = sorted({
        line.split()[0] for line in undefined_output.splitlines() if line.strip()
    })
    if not undefined:
        fail("module has no undefined ELF symbols")

    map_results: list[tuple[str, int]] = []
    for system_map in args.system_map:
        counts: Counter[str] = Counter()
        for line in system_map.read_text(errors="replace").splitlines():
            fields_map = line.split()
            if len(fields_map) >= 3:
                counts[fields_map[2]] += 1
        missing = [name for name in undefined if counts[name] == 0]
        ambiguous = [name for name in undefined if counts[name] > 1]
        if missing or ambiguous:
            fail(
                f"non-unique symbols in {system_map.name}: "
                f"missing={missing}, ambiguous={ambiguous}"
            )
        map_results.append((system_map.name, len(undefined)))

    exports = set()
    for line in args.symvers.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            exports.add(parts[1])
    non_exported = sorted(set(undefined) - exports)

    module_data = args.module.read_bytes()
    if args.expected_manager_package.encode("ascii") not in module_data:
        fail("dedicated manager package marker is absent")
    if args.expected_cert_hash.lower().encode("ascii") not in module_data.lower():
        fail("dedicated manager certificate hash is absent")

    lines = [
        "# Static validation — ReSukiSU TCL V65x candidate",
        "",
        "Result: **STATIC PASS / LOAD NOT AUTHORIZED**.",
        "",
        f"- Module: `{args.module.name}`",
        f"- SHA-256: `{sha256(args.module)}`",
        f"- Size: `{args.module.stat().st_size}` bytes",
        f"- Vermagic: `{expected_vermagic}`",
        "- Compiler: Android Clang 17.0.2 `r487747c`",
        "- ARM64 property: PAC present; BTI absent",
        f"- Undefined ELF symbols: `{len(undefined)}`",
        f"- Exported imports: `{len(set(undefined) & exports)}`",
        f"- Private symbols requiring ReSukiSU relocation: `{len(non_exported)}`",
        f"- Manager package: `{args.expected_manager_package}`",
        f"- Manager certificate SHA-256: `{args.expected_cert_hash.lower()}`",
        "",
        "## Exact System.map resolution",
        "",
    ]
    lines.extend(f"- `{name}`: `{count}/{count}` unique" for name, count in map_results)
    lines.extend((
        "",
        "## Private symbols",
        "",
        "```text",
        *non_exported,
        "```",
        "",
        "These checks prove static symbol identity only. They do not authorize",
        "module loading or establish runtime safety on a television.",
        "",
    ))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_name(args.report.name + ".tmp")
    temporary.write_text("\n".join(lines), encoding="utf-8")
    temporary.replace(args.report)

    print(f"undefined_symbols={len(undefined)}")
    print(f"private_symbols={len(non_exported)}")
    print(f"system_maps={len(map_results)}")
    print(f"report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
