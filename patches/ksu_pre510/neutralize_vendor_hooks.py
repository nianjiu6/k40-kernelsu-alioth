#!/usr/bin/env python3
"""Retarget vendor 0.9.5 CONFIG_KSU syscall patches to CONFIG_KSU_MANUAL_HOOK.

Official KernelSU 3.x hooks via kprobes/tracepoints and no longer exports
ksu_execveat_hook, ksu_handle_faccessat, ksu_handle_sys_read, ksu_input_hook,
ksu_handle_devpts, ksu_handle_stat, or the 0.9.5 ksu_handle_execveat_sucompat
prototype. Xiaomi alioth already has those call sites under CONFIG_KSU; leaving
them compiled against 3.x both fails the link and would call 3.x
ksu_handle_execveat_sucompat with the wrong arguments.

Exact token CONFIG_KSU is rewritten; CONFIG_KSU_SUSFS and similar stay.
Makefiles / Kconfig / defconfig are left alone so obj-$(CONFIG_KSU) += kernelsu/
still builds the 3.x driver.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "out",
    "kernelsu",
    "KernelSU",
    "KernelSU-Next",
    "Documentation",
    "tools",
    "samples",
    "scripts",
    "usr",
}

TOKEN = re.compile(r"\bCONFIG_KSU\b")


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: neutralize_vendor_hooks.py <kernel-dir>")
    root = Path(sys.argv[1]).resolve()
    tokens = 0
    files = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".c", ".h", ".S"}:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "CONFIG_KSU" not in text:
            continue
        new, count = TOKEN.subn("CONFIG_KSU_MANUAL_HOOK", text)
        if not count:
            continue
        path.write_text(new, encoding="utf-8")
        tokens += count
        files += 1
        print(f"  {path.relative_to(root)}: {count}")
    print(f"neutralized {tokens} CONFIG_KSU tokens in {files} vendor files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
