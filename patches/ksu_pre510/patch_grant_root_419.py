#!/usr/bin/env python3
"""4.19 grant_root: do not depend on kprobes, seccomp action_cache, or CONFIG_KSU.

Manager/libksud get the driver fd via reboot(0xDEADBEEF, 0xCAFEBABE, 0, &fd).
On GKI that works because:

  1. setresuid of the Manager UID caches __NR_reboot as ALLOW (5.11+ bitmap)
  2. kprobe on __arm64_sys_reboot queues ksu_install_fd via task_work

4.19 has neither. untrusted_app seccomp SIGSYS's reboot before the kprobe
runs, and ksu_seccomp_allow_cache is compiled as a no-op.

Do NOT wrap these hooks in #ifdef CONFIG_KSU. Xiaomi 4.19 may link
kernelsu/ via obj-y while syncconfig drops the unknown/unmet CONFIG_KSU
symbol, so the ifdef compiles the hooks out and Manager shows
grant_root_failed. The linker still requires ksu_try_install_fd.
"""
from __future__ import annotations

import sys
from pathlib import Path

DONE = "ksu_grant_root_419 reboot"

SECCOMP_STOCK = """\tthis_syscall = sd ? sd->nr :
\t\tsyscall_get_nr(current, task_pt_regs(current));

\tswitch (mode) {
"""

SECCOMP_IFDEF = """\tthis_syscall = sd ? sd->nr :
\t\tsyscall_get_nr(current, task_pt_regs(current));

#ifdef CONFIG_KSU
\t/* KSU_GRANT_ROOT_419: GKI uses seccomp action_cache (5.11+). 4.19 has
\t * none, so untrusted_app SIGSYS's reboot(DEADBEEF, CAFEBABE) before
\t * KernelSU's kprobe/syscall handler can install the driver fd. */
\tif (this_syscall == __NR_reboot) {
\t\tunsigned long a0, a1;

\t\tif (sd) {
\t\t\ta0 = sd->args[0];
\t\t\ta1 = sd->args[1];
\t\t} else {
\t\t\tunsigned long args[2];

\t\t\tsyscall_get_arguments(current, task_pt_regs(current), 0, 2, args);
\t\t\ta0 = args[0];
\t\t\ta1 = args[1];
\t\t}
\t\tif ((unsigned int)a0 == 0xDEADBEEF && (unsigned int)a1 == 0xCAFEBABE)
\t\t\treturn 0;
\t}
#endif

\tswitch (mode) {
"""

SECCOMP_ALWAYS = """\tthis_syscall = sd ? sd->nr :
\t\tsyscall_get_nr(current, task_pt_regs(current));

\t/* KSU_GRANT_ROOT_419_ALWAYS: never gate on CONFIG_KSU. */
\tif (this_syscall == __NR_reboot) {
\t\tunsigned long a0, a1;

\t\tif (sd) {
\t\t\ta0 = sd->args[0];
\t\t\ta1 = sd->args[1];
\t\t} else {
\t\t\tunsigned long args[2];

\t\t\tsyscall_get_arguments(current, task_pt_regs(current), 0, 2, args);
\t\t\ta0 = args[0];
\t\t\ta1 = args[1];
\t\t}
\t\tif ((unsigned int)a0 == 0xDEADBEEF && (unsigned int)a1 == 0xCAFEBABE)
\t\t\treturn 0;
\t}

\tswitch (mode) {
"""

REBOOT_STOCK = """SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	char buffer[256];
	int ret = 0;

	/* We only trust the superuser with rebooting the system. */
	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
		return -EPERM;
"""

REBOOT_IFDEF = """SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	char buffer[256];
	int ret = 0;

#ifdef CONFIG_KSU
	/* KSU_GRANT_ROOT_419: install the driver fd before CAP_SYS_BOOT.
	 * The original handler would return -EPERM for untrusted_app. */
	if ((unsigned int)magic1 == 0xDEADBEEF &&
	    (unsigned int)magic2 == 0xCAFEBABE) {
		extern int ksu_try_install_fd(void __user *outp);

		return ksu_try_install_fd(arg);
	}
#endif

	/* We only trust the superuser with rebooting the system. */
	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
		return -EPERM;
"""

REBOOT_ALWAYS = """SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,
		void __user *, arg)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(current);
	char buffer[256];
	int ret = 0;

	/* KSU_GRANT_ROOT_419_ALWAYS: never gate on CONFIG_KSU. */
	if ((unsigned int)magic1 == 0xDEADBEEF &&
	    (unsigned int)magic2 == 0xCAFEBABE) {
		extern int ksu_try_install_fd(void __user *outp);

		pr_info("ksu_grant_root_419 reboot\\n");
		return ksu_try_install_fd(arg);
	}

	/* We only trust the superuser with rebooting the system. */
	if (!ns_capable(pid_ns->user_ns, CAP_SYS_BOOT))
		return -EPERM;
"""

SETRESUID_STOCK = """	retval = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	return commit_creds(new);
"""

SETRESUID_IFDEF = """	retval = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

#ifdef CONFIG_KSU
	{
		/* KSU_GRANT_ROOT_419: GKI kretprobe on setresuid installs the
		 * Manager fd. 4.19 often has CONFIG_KPROBES=n. */
		extern int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid);
		uid_t ksu_old_uid = from_kuid(&init_user_ns, old->uid);

		retval = commit_creds(new);
		if (!retval)
			ksu_handle_setresuid(ksu_old_uid,
					     from_kuid(&init_user_ns, current_uid()));
		return retval;
	}
#else
	return commit_creds(new);
#endif
"""

SETRESUID_ALWAYS = """	retval = security_task_fix_setuid(new, old, LSM_SETID_RES);
	if (retval < 0)
		goto error;

	{
		/* KSU_GRANT_ROOT_419_ALWAYS: never gate on CONFIG_KSU. */
		extern int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid);
		uid_t ksu_old_uid = from_kuid(&init_user_ns, old->uid);

		retval = commit_creds(new);
		if (!retval)
			ksu_handle_setresuid(ksu_old_uid,
					     from_kuid(&init_user_ns, current_uid()));
		return retval;
	}
"""


def patch_file(path: Path, olds: list[str], new: str, label: str, done: str) -> None:
    if not path.is_file():
        sys.exit(f"4.19 grant_root: missing {path}")
    text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    if done in text:
        print(f"already patched: {path} ({label})")
        return
    for old in olds:
        if old in text:
            path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
            print(f"patched 4.19 grant_root {label}: {path}")
            return
    sys.exit(f"4.19 grant_root: missing marker for {label} in {path}")


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: patch_grant_root_419.py <kernel-tree>")
    kernel = Path(sys.argv[1])
    patch_file(
        kernel / "kernel" / "seccomp.c",
        [SECCOMP_IFDEF, SECCOMP_STOCK],
        SECCOMP_ALWAYS,
        "seccomp reboot-magic",
        "KSU_GRANT_ROOT_419_ALWAYS",
    )
    patch_file(
        kernel / "kernel" / "reboot.c",
        [REBOOT_IFDEF, REBOOT_STOCK],
        REBOOT_ALWAYS,
        "reboot install_fd",
        DONE,
    )
    patch_file(
        kernel / "kernel" / "sys.c",
        [SETRESUID_IFDEF, SETRESUID_STOCK],
        SETRESUID_ALWAYS,
        "setresuid hook",
        "KSU_GRANT_ROOT_419_ALWAYS",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
