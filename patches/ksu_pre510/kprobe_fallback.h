#ifndef __KSU_H_KPROBE_FALLBACK
#define __KSU_H_KPROBE_FALLBACK

void ksu_kprobe_fallback_init(void);
void ksu_kprobe_fallback_exit(void);

/* Called from patched kernel/seccomp.c. Always reads magics from pt_regs. */
int ksu_seccomp_may_allow_reboot(int nr);
void ksu_seccomp_mark_reboot_allowed(void *filter);

#endif
