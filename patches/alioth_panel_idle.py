#!/usr/bin/env python3
"""Alioth panel: disable SDE idle *timeout* default (100ms sysfs_notify).

Do not clear IDLE_ENCODER_MASK_DEFAULT. Mask=0 makes idle_state always
"idle", and the vendor display HAL then power-collapses the OLED at boot.
"""
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

    panel = kdir / "techpack/display/msm/dsi/dsi_panel.c"
    if panel.is_file():
        text = panel.read_text(encoding="utf-8", errors="replace")
        needle = "len = utils->count_u32_elems(utils->data, \"mi,mdss-dsi-dimlayer-brightness-alpha-lut\");"
        if needle in text and "fod_dim_lut_count = 0;\n\t\treturn 0;" not in text:
            text = text.replace(
                needle
                + "\n\tif (len <= 0 || len % BRIGHTNESS_ALPHA_PAIR_LEN) {",
                needle
                + "\n\tif (len <= 0) {\n"
                + "\t\tpanel->fod_dim_lut = NULL;\n"
                + "\t\tpanel->fod_dim_lut_count = 0;\n"
                + "\t\treturn 0;\n"
                + "\t}\n"
                + "\tif (len % BRIGHTNESS_ALPHA_PAIR_LEN) {",
                1,
            )
            print("patched dsi_panel_parse_fod_dim_lut missing-lut -> success")
        restore_anchor = (
            "\tmi_cfg->into_aod_pending = false;\n"
            "\tmi_cfg->cabc_current_status = 0;\n\n"
            "\tmutex_unlock(&panel->panel_lock);"
        )
        restore_new = (
            "\tmi_cfg->into_aod_pending = false;\n"
            "\tmi_cfg->cabc_current_status = 0;\n"
            "\n"
            "\tif (mi_cfg->last_nonzero_bl_level) {\n"
            "\t\tDSI_INFO(\"restore backlight %u after panel on\\n\",\n"
            "\t\t\t mi_cfg->last_nonzero_bl_level);\n"
            "\t\tpanel->bl_config.bl_level = mi_cfg->last_nonzero_bl_level;\n"
            "\t\tdsi_panel_update_backlight(panel, mi_cfg->last_nonzero_bl_level);\n"
            "\t\tmi_cfg->last_bl_level = mi_cfg->last_nonzero_bl_level;\n"
            "\t}\n"
            "\n"
            "\tmutex_unlock(&panel->panel_lock);"
        )
        if "restore backlight %u after panel on" not in text:
            if restore_anchor not in text:
                print("warn: dsi_panel_enable restore anchor not found", file=sys.stderr)
                ok = False
            else:
                text = text.replace(restore_anchor, restore_new, 1)
                print("patched dsi_panel_enable to restore last_nonzero_bl_level")
        panel.write_text(text, encoding="utf-8")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
