#!/usr/bin/env python3
"""Alioth HyperOS panel: use Xiaomi MIUI display stack, skip bad LHBM reads.

HyperOS vendor + AOSP/Lineage `techpack/display/msm` compositor still paints
(the framebuffer / scrcpy path) but never drives the OLED via Xiaomi
displayfeature / mi_disp_lhbm. The stock Image contains those files; lineage-20
msm/ does not. sm8250_mod ships a parallel tree at msm-miui/ selected by
CONFIG_XIAOMI_MIUI.

Also:
- do not clear IDLE_ENCODER_MASK_DEFAULT (mask=0 => idle_state always idle)
- default IDLE_TIMEOUT_MS to 0 so the 100ms sysfs_notify does not fire
- missing FOD dim lut is not a probe error
- skip LHBM white-param DSI reads when the DTB has no read cmds (rc=-11 at
  first unblank glitches ELVSS / 51h)
- restore last_nonzero_bl_level after SET_ON
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


def patch_idle_timeout(msm: Path) -> bool:
    if not msm.is_file():
        return False
    if replace_once(
        msm,
        "#define IDLE_TIMEOUT_MS_DEFAULT\t\t100",
        "#define IDLE_TIMEOUT_MS_DEFAULT\t\t0",
    ) or replace_once(
        msm,
        "#define IDLE_TIMEOUT_MS_DEFAULT 100",
        "#define IDLE_TIMEOUT_MS_DEFAULT 0",
    ):
        print(f"patched IDLE_TIMEOUT_MS_DEFAULT -> 0 in {msm}")
        return True
    print(f"warn: IDLE_TIMEOUT_MS_DEFAULT not patched in {msm}", file=sys.stderr)
    return False


def patch_fod_lut_and_restore(panel: Path) -> None:
    if not panel.is_file():
        return
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
        print(f"patched dsi_panel_parse_fod_dim_lut missing-lut -> success in {panel}")
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
            print(f"warn: dsi_panel_enable restore anchor not found in {panel}", file=sys.stderr)
        else:
            text = text.replace(restore_anchor, restore_new, 1)
            print(f"patched dsi_panel_enable to restore last_nonzero_bl_level in {panel}")
    panel.write_text(text, encoding="utf-8")


def skip_lhbm_read(src: Path) -> None:
    if not src.is_file():
        return
    text = src.read_text(encoding="utf-8", errors="replace")
    marker = "/* alioth: skip LHBM white-param DSI read"
    if marker in text:
        print(f"lhbm skip already present in {src}")
        return
    sigs = [
        "int mi_dsi_panel_read_lhbm_white_param(struct dsi_panel *panel)\n{\n",
        "int mi_dsi_panel_read_lhbm_white_param(struct dsi_panel *panel)\n{\r\n",
        "int mi_dsi_panel_read_lhbm_white_param(struct dsi_panel *panel) {\n",
    ]
    for sig in sigs:
        if sig in text:
            text = text.replace(
                sig,
                sig + f"\t{marker} at first unblank */\n\treturn 0;\n",
                1,
            )
            src.write_text(text, encoding="utf-8")
            print(f"patched mi_dsi_panel_read_lhbm_white_param -> return 0 in {src}")
            return
    print(f"warn: mi_dsi_panel_read_lhbm_white_param not found in {src}", file=sys.stderr)


def patch_miui_drm_symbols(kdir: Path) -> bool:
    """msm-miui links against Xiaomi drm_sysfs globals that AOSP drm_sysfs.c
    does not provide. Provide connector_kdev + identity PCC so vmlinux links.
    """
    ok = True
    sysfs = kdir / "drivers/gpu/drm/drm_sysfs.c"
    if not sysfs.is_file():
        print(f"warn: {sysfs} missing", file=sys.stderr)
        return False
    text = sysfs.read_text(encoding="utf-8", errors="replace")
    if "struct device *connector_kdev" not in text:
        if "struct class *drm_class;" not in text:
            print("warn: drm_class anchor missing in drm_sysfs.c", file=sys.stderr)
            ok = False
        else:
            text = text.replace(
                "struct class *drm_class;",
                "struct class *drm_class;\nstruct device *connector_kdev;",
                1,
            )
            print("defined connector_kdev in drm_sysfs.c")
    if "connector_kdev = connector->kdev" not in text:
        err_anchor = (
            "\tif (IS_ERR(connector->kdev)) {\n"
            "\t\tDRM_ERROR(\"failed to register connector device: %ld\\n\", PTR_ERR(connector->kdev));"
        )
        err_new = (
            "\tif (!connector_kdev)\n"
            "\t\tconnector_kdev = connector->kdev;\n"
            "\n"
            + err_anchor
        )
        if err_anchor not in text:
            print("warn: drm_sysfs_connector_add IS_ERR anchor not found", file=sys.stderr)
            ok = False
        else:
            text = text.replace(err_anchor, err_new, 1)
            print("patched drm_sysfs_connector_add to set connector_kdev")
    sysfs.write_text(text, encoding="utf-8")

    pcc_def = (
        "struct drm_msm_pcc color_transform_pcc_cfg = {\n"
        "\t.r.c = 0, .r.r = 32768, .r.g = 0, .r.b = 0,\n"
        "\t.g.c = 0, .g.r = 0, .g.g = 32768, .g.b = 0,\n"
        "\t.b.c = 0, .b.r = 0, .b.g = 0, .b.b = 32768,\n"
        "};"
    )
    pcc = kdir / "techpack/display/msm-miui/sde/sde_color_processing.c"
    if pcc.is_file():
        ptext = pcc.read_text(encoding="utf-8", errors="replace")
        if "extern struct drm_msm_pcc color_transform_pcc_cfg;" in ptext:
            ptext = ptext.replace(
                "extern struct drm_msm_pcc color_transform_pcc_cfg;",
                pcc_def,
                1,
            )
            pcc.write_text(ptext, encoding="utf-8")
            print("defined color_transform_pcc_cfg identity PCC in sde_color_processing.c")
        elif "color_transform_pcc_cfg =" in ptext:
            print("color_transform_pcc_cfg already defined")
        else:
            print("warn: color_transform_pcc_cfg extern not found", file=sys.stderr)
            ok = False
    else:
        print(f"warn: {pcc} missing", file=sys.stderr)
        ok = False

    atomic = kdir / "techpack/display/msm-miui/msm_atomic.c"
    if atomic.is_file():
        atext = atomic.read_text(encoding="utf-8", errors="replace")
        old_notify = (
            "sysfs_notify(&connector_kdev->kobj, NULL, \"complete_commit_time\");"
        )
        new_notify = (
            "if (connector_kdev)\n"
            "\t\tsysfs_notify(&connector_kdev->kobj, NULL, \"complete_commit_time\");"
        )
        if old_notify in atext and "if (connector_kdev)" not in atext:
            atext = atext.replace(old_notify, new_notify, 1)
            atomic.write_text(atext, encoding="utf-8")
            print("null-checked connector_kdev in complete_time_generate_event")
    return ok


def enable_miui_display(kdir: Path) -> bool:
    miui_dir = kdir / "techpack/display/msm-miui"
    if not miui_dir.is_dir():
        print("warn: techpack/display/msm-miui missing; cannot select Xiaomi display stack", file=sys.stderr)
        return False
    conf = kdir / "techpack/display/config/konadisp.conf"
    if not conf.is_file():
        print(f"warn: {conf} missing", file=sys.stderr)
        return False
    text = conf.read_text(encoding="utf-8", errors="replace")
    if "CONFIG_XIAOMI_MIUI" in text:
        print("CONFIG_XIAOMI_MIUI already in konadisp.conf")
        return True
    if "export CONFIG_DRM_MSM=y" not in text:
        print("warn: export CONFIG_DRM_MSM=y not in konadisp.conf", file=sys.stderr)
        return False
    conf.write_text(
        text.replace(
            "export CONFIG_DRM_MSM=y",
            "export CONFIG_DRM_MSM=y\nexport CONFIG_XIAOMI_MIUI=y",
            1,
        ),
        encoding="utf-8",
    )
    print("patched konadisp.conf: export CONFIG_XIAOMI_MIUI=y (msm-miui)")
    return True


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: alioth_panel_idle.py KERNEL_DIR", file=sys.stderr)
        return 2
    kdir = Path(sys.argv[1])

    miui = enable_miui_display(kdir)
    drm_ok = patch_miui_drm_symbols(kdir) if miui else False

    display_roots = [
        kdir / "techpack/display/msm",
        kdir / "techpack/display/msm-miui",
    ]
    idle_hit = False
    for root in display_roots:
        idle_hit = patch_idle_timeout(root / "msm_drv.c") or idle_hit
        patch_fod_lut_and_restore(root / "dsi/dsi_panel.c")
        skip_lhbm_read(root / "dsi/dsi_panel_mi.c")
        skip_lhbm_read(root / "dsi/mi_dsi_panel.c")
    if not idle_hit:
        print("warn: IDLE_TIMEOUT_MS_DEFAULT not patched in any msm_drv.c", file=sys.stderr)

    # msm-miui + drm_sysfs Xiaomi globals are required to link.
    return 0 if miui and drm_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
