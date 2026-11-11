#!/usr/bin/env bash
# Run the KernelSU Action pipeline outside GitHub Actions.
# Usage: CONFIG_ENV=config.env bash scripts/local-run.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export WORKSPACE="${WORKSPACE:-$HOME/k40ksu-ws/kernel_workspace}"
export CONFIG_ENV="${CONFIG_ENV:-config.env}"
export GITHUB_ENV="${GITHUB_ENV:-$HOME/k40ksu-ws/github.env}"
export GITHUB_STEP_SUMMARY="${GITHUB_STEP_SUMMARY:-$HOME/k40ksu-ws/summary.md}"
export JOBS="${JOBS:-6}"
export CCACHE_DIR="${CCACHE_DIR:-$HOME/k40ksu-ws/.ccache}"
mkdir -p "$WORKSPACE" "$(dirname "$GITHUB_ENV")"
: >"$GITHUB_ENV"
: >"$GITHUB_STEP_SUMMARY"

load_github_env() {
	python3 - <<'PY'
import os, pathlib
p = pathlib.Path(os.environ["GITHUB_ENV"])
if not p.exists():
    raise SystemExit(0)
text = p.read_text(encoding="utf-8", errors="replace")
out = []
i = 0
lines = text.splitlines()
while i < len(lines):
    line = lines[i]
    if "<<__GHEOF_" in line:
        key, delim = line.split("<<", 1)
        i += 1
        val = []
        while i < len(lines) and lines[i] != delim:
            val.append(lines[i])
            i += 1
        i += 1
        out.append((key, "\n".join(val)))
    elif line.strip() and not line.startswith("#") and "=" in line:
        key, val = line.split("=", 1)
        out.append((key, val))
        i += 1
    else:
        i += 1
dst = pathlib.Path(os.environ["GITHUB_ENV"]).with_suffix(".exports")
body = []
for k, v in out:
    body.append("export %s=%s" % (k, repr(v)))
dst.write_text("\n".join(body) + "\n", encoding="utf-8")
print(str(dst))
PY
}

run_step() {
	local title=$1
	shift
	echo "======== ${title} ========"
	bash "$@"
	local exp
	exp=$(load_github_env)
	# shellcheck disable=SC1090
	[ -n "$exp" ] && [ -f "$exp" ] && set -a && . "$exp" && set +a
}

run_step "Resolve configuration" "$ROOT/scripts/config.sh"
run_step "Set up toolchain" "$ROOT/scripts/toolchain.sh"
run_step "Fetch kernel source" "$ROOT/scripts/source.sh"
run_step "Install KernelSU" "$ROOT/scripts/kernelsu.sh"
run_step "Apply kernel patches" "$ROOT/scripts/patches.sh" all
run_step "Build kernel" "$ROOT/scripts/build.sh" all
run_step "Package artifacts" "$ROOT/scripts/package.sh" all

echo "======== done ========"
echo "Image: ${KERNEL_DIR}/out/arch/${ARCH}/boot/${KERNEL_IMAGE_NAME}"
ls -l "${KERNEL_DIR}/out/arch/${ARCH}/boot/${KERNEL_IMAGE_NAME}"
