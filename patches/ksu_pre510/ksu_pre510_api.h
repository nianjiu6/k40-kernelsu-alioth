#ifndef __KSU_PRE510_API_H
#define __KSU_PRE510_API_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
#ifndef MODULE_IMPORT_NS
#define MODULE_IMPORT_NS(ns)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#ifndef strncpy_from_user_nofault
#define strncpy_from_user_nofault strncpy_from_user
#endif
#ifndef copy_from_kernel_nofault
#define copy_from_kernel_nofault(dst, src, size) probe_kernel_read((dst), (src), (size))
#endif
#ifndef copy_to_kernel_nofault
#define copy_to_kernel_nofault(dst, src, size) probe_kernel_write((dst), (src), (size))
#endif
#ifndef copy_from_user_nofault
#define copy_from_user_nofault copy_from_user
#endif
#ifndef copy_to_user_nofault
#define copy_to_user_nofault copy_to_user
#endif
#endif

/* seccomp bitmap cache landed in 5.11; 4.19 still uses __NR_syscalls. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#ifndef SECCOMP_ARCH_NATIVE_NR
#define SECCOMP_ARCH_NATIVE_NR __NR_syscalls
#endif
#endif

/* task_work_add() took a bool notify until 5.7; TWA_RESUME == notify. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0)
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#ifndef fallthrough
#define fallthrough __attribute__((__fallthrough__))
#endif
#ifndef selinux_cred
#define selinux_cred(cred) ((cred)->security)
#endif
#ifndef selinux_inode
#define selinux_inode(inode) ((inode)->i_security)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
#ifndef strscpy_pad
#define strscpy_pad(dest, src, count) strlcpy((dest), (src), (count))
#endif
#endif

#endif
