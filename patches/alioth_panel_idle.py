#!/usr/bin/env python3
"""Alioth panel: disable SDE idle PC default (100ms idle blacks the OLED after first blank)."""
from __future__ import annotations

import sys
from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> bool:
    text = path.read_text(encoding="utf-8", errors="replace")
    if old not in text:
        return False
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: alioth_panel_idle.py KERNEL_DIR", file=sys.stderr)
        return 2
    kdir = Path(sys.argv[1])
    msm = kdir / "techpack/display/msm/msm_drv.c"
    if not msm.is_file():
        print(f"skip: {msm} missing")
        return 0

    ok = True
    if not replace_once(
        msm,
        "#define IDLE_TIMEOUT_MS_DEFAULT\t\t100",
        "#define IDLE_TIMEOUT_MS_DEFAULT\t\t0",
    ) and not replace_once(
        msm,
        "#define IDLE_TIMEOUT_MS_DEFAULT 100",
        "#define IDLE_TIMEOUT_MS_DEFAULT 0",
    ):
        print("warn: IDLE_TIMEOUT_MS_DEFAULT not patched", file=sys.stderr)
        ok = False
    else:
        print("patched IDLE_TIMEOUT_MS_DEFAULT -> 0")

    if not replace_once(
        msm,
        "#define IDLE_ENCODER_MASK_DEFAULT\t1",
        "#define IDLE_ENCODER_MASK_DEFAULT\t0",
    ) and not replace_once(
        msm,
        "#define IDLE_ENCODER_MASK_DEFAULT 1",
        "#define IDLE_ENCODER_MASK_DEFAULT 0",
    ):
        print("warn: IDLE_ENCODER_MASK_DEFAULT not patched", file=sys.stderr)
        ok = False
    else:
        print("patched IDLE_ENCODER_MASK_DEFAULT -> 0")

    panel = kdir / "techpack/display/msm/dsi/dsi_panel.c"
    if panel.is_file():
        text = panel.read_text(encoding="utf-8", errors="replace")
        needle = "len = utils->count_u32_elems(utils->data, \"mi,mdss-dsi-dimlayer-brightness-alpha-lut\");"
        insert = (
            "len = utils->count_u32_elems(utils->data, \"mi,mdss-dsi-dimlayer-brightness-alpha-lut\");\n"
            "\tif (len <= 0) {\n"
            "\t\tpanel->fod_dim_lut = NULL;\n"
            "\t\tpanel->fod_dim_lut_count = 0;\n"
            "\t\treturn 0;\n"
            "\t}"
        )
        if needle in text and "return 0;\n\t}\n\n\tarray = kcalloc(len" not in text:
            text = text.replace(
                needle
                + "\n\tif (len <= 0 || len % BRIGHTNESS_ALPHA_PAIR_LEN) {",
                insert
                + "\n\tif (len % BRIGHTNESS_ALPHA_PAIR_LEN) {",
                1,
            )
            panel.write_text(text, encoding="utf-8")
            print("patched dsi_panel_parse_fod_dim_lut missing-lut -> success")
        else:
            print("fod dim lut parse already optional or unexpected layout")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
