// SPDX-License-Identifier: GPL-2.0
/*
 * 4.19 fallback when sys_call_table poke is dead or seccomp has no action_cache.
 *
 * 1. __secure_computing: allow KernelSU reboot-magic so Manager can get the
 *    driver fd (GKI uses seccomp action_cache, which 4.19 does not have).
 * 2. If the dispatcher slot was not installed, kprobe execve/execveat and
 *    kretprobe setresuid so post-fs-data / manager crowning still run.
 */
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <linux/syscalls.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

#include "arch.h"
#include "hook/kprobe_fallback.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "klog.h"
#include "runtime/ksud.h"
#include "uapi/supercall.h"

static int seccomp_reboot_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real;
    int nr;

    (void)p;
    (void)regs;
    if (current->seccomp.mode != SECCOMP_MODE_FILTER)
        return 0;
    real = task_pt_regs(current);
    if (!real)
        return 0;
    nr = syscall_get_nr(current, real);
    if (nr != __NR_reboot)
        return 0;
    if ((unsigned int)PT_REGS_SYSCALL_PARM1(real) != KSU_INSTALL_MAGIC1)
        return 0;
    if ((unsigned int)PT_REGS_PARM2(real) != KSU_INSTALL_MAGIC2)
        return 0;
    current->seccomp.mode = SECCOMP_MODE_DISABLED;
    return 0;
}

static void seccomp_reboot_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct pt_regs *real;
    int nr;

    (void)p;
    (void)regs;
    (void)flags;
    real = task_pt_regs(current);
    if (!real)
        return;
    nr = syscall_get_nr(current, real);
    if (nr != __NR_reboot)
        return;
    if ((unsigned int)PT_REGS_SYSCALL_PARM1(real) != KSU_INSTALL_MAGIC1)
        return;
    if (current->seccomp.mode == SECCOMP_MODE_DISABLED)
        current->seccomp.mode = SECCOMP_MODE_FILTER;
}

static struct kprobe seccomp_kp = {
    .symbol_name = "__secure_computing",
    .pre_handler = seccomp_reboot_pre,
    .post_handler = seccomp_reboot_post,
};

static int execve_pre(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    ksu_execve_hook_ksud(PT_REAL_REGS(regs));
    return 0;
}

static int execveat_pre(struct kprobe *p, struct pt_regs *regs)
{
    (void)p;
    ksu_execveat_hook_ksud(PT_REAL_REGS(regs));
    return 0;
}

static struct kprobe execve_kp = {
    .symbol_name = SYS_EXECVE_SYMBOL,
    .pre_handler = execve_pre,
};

static struct kprobe execveat_kp = {
    .symbol_name = "__arm64_sys_execveat",
    .pre_handler = execveat_pre,
};

#ifdef CONFIG_KRETPROBES
struct setresuid_priv {
    uid_t old_uid;
};

static int setresuid_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct setresuid_priv *priv = (struct setresuid_priv *)ri->data;

    (void)regs;
    priv->old_uid = current_uid().val;
    return 0;
}

static int setresuid_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct setresuid_priv *priv = (struct setresuid_priv *)ri->data;
    long rc = (long)PT_REGS_RC(regs);

    if (rc < 0)
        return 0;
    ksu_handle_setresuid(priv->old_uid, current_uid().val);
    return 0;
}

static struct kretprobe setresuid_rp = {
    .kp.symbol_name = "__arm64_sys_setresuid",
    .entry_handler = setresuid_entry,
    .handler = setresuid_ret,
    .data_size = sizeof(struct setresuid_priv),
    .maxactive = 0,
};
#endif

static bool seccomp_kp_ok;
static bool execve_kp_ok;
static bool execveat_kp_ok;
#ifdef CONFIG_KRETPROBES
static bool setresuid_rp_ok;
#endif

void ksu_kprobe_fallback_init(void)
{
    int rc;

    rc = register_kprobe(&seccomp_kp);
    if (rc) {
        pr_err("kprobe_fallback: __secure_computing: %d\n", rc);
    } else {
        seccomp_kp_ok = true;
        pr_info("kprobe_fallback: reboot-magic seccomp bypass registered\n");
    }

    if (ksu_dispatcher_nr >= 0) {
        pr_info("kprobe_fallback: dispatcher live at slot %d, skip execve/setresuid kprobes\n",
                ksu_dispatcher_nr);
        return;
    }

    rc = register_kprobe(&execve_kp);
    if (rc) {
        pr_err("kprobe_fallback: execve: %d\n", rc);
    } else {
        execve_kp_ok = true;
        pr_info("kprobe_fallback: execve kprobe registered\n");
    }

    rc = register_kprobe(&execveat_kp);
    if (rc) {
        pr_err("kprobe_fallback: execveat: %d\n", rc);
    } else {
        execveat_kp_ok = true;
        pr_info("kprobe_fallback: execveat kprobe registered\n");
    }

#ifdef CONFIG_KRETPROBES
    rc = register_kretprobe(&setresuid_rp);
    if (rc) {
        pr_err("kprobe_fallback: setresuid kretprobe: %d\n", rc);
    } else {
        setresuid_rp_ok = true;
        pr_info("kprobe_fallback: setresuid kretprobe registered\n");
    }
#endif
}

void ksu_kprobe_fallback_exit(void)
{
#ifdef CONFIG_KRETPROBES
    if (setresuid_rp_ok)
        unregister_kretprobe(&setresuid_rp);
#endif
    if (execveat_kp_ok)
        unregister_kprobe(&execveat_kp);
    if (execve_kp_ok)
        unregister_kprobe(&execve_kp);
    if (seccomp_kp_ok)
        unregister_kprobe(&seccomp_kp);
}
