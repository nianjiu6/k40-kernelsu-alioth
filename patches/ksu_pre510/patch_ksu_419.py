#!/usr/bin/env python3
"""Guard official KernelSU 3.x sources against APIs missing on 4.19.

Applied after checkout, only on kernels older than 5.10. Upstream file_wrapper.c
still assumes GKI 5.10+: iopoll (5.1), remap_file_range (4.20), and
security_inode_init_security_anon (5.7). Xiaomi alioth 4.19 has none of those.
"""
from __future__ import annotations

import sys
from pathlib import Path

IOPOLL_OLD = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int ksu_wrapper_iopoll(struct kiocb *kiocb, struct io_comp_batch *icb, unsigned int v)
{
    struct ksu_file_wrapper *data = kiocb->ki_filp->private_data;
    struct file *orig = data->orig;
    kiocb->ki_filp = orig;
    return orig->f_op->iopoll(kiocb, icb, v);
}
#else
static int ksu_wrapper_iopoll(struct kiocb *kiocb, bool spin)
{
    struct ksu_file_wrapper *data = kiocb->ki_filp->private_data;
    struct file *orig = data->orig;
    kiocb->ki_filp = orig;
    return orig->f_op->iopoll(kiocb, spin);
}
#endif
"""

IOPOLL_NEW = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static int ksu_wrapper_iopoll(struct kiocb *kiocb, struct io_comp_batch *icb, unsigned int v)
{
    struct ksu_file_wrapper *data = kiocb->ki_filp->private_data;
    struct file *orig = data->orig;
    kiocb->ki_filp = orig;
    return orig->f_op->iopoll(kiocb, icb, v);
}
#else
static int ksu_wrapper_iopoll(struct kiocb *kiocb, bool spin)
{
    struct ksu_file_wrapper *data = kiocb->ki_filp->private_data;
    struct file *orig = data->orig;
    kiocb->ki_filp = orig;
    return orig->f_op->iopoll(kiocb, spin);
}
#endif
#endif
"""

REMAP_OLD = """static loff_t ksu_wrapper_remap_file_range(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out,
                                           loff_t len, unsigned int remap_flags)
{
    if (remap_flags & REMAP_FILE_DEDUP) {
        struct ksu_file_wrapper *data = file_out->private_data;
        struct file *orig = data->orig;
        return orig->f_op->remap_file_range(file_in, pos_in, orig, pos_out, len, remap_flags);
    } else {
        struct ksu_file_wrapper *data = file_in->private_data;
        struct file *orig = data->orig;
        return orig->f_op->remap_file_range(orig, pos_in, file_out, pos_out, len, remap_flags);
    }
}
"""

REMAP_NEW = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
static loff_t ksu_wrapper_remap_file_range(struct file *file_in, loff_t pos_in, struct file *file_out, loff_t pos_out,
                                           loff_t len, unsigned int remap_flags)
{
    if (remap_flags & REMAP_FILE_DEDUP) {
        struct ksu_file_wrapper *data = file_out->private_data;
        struct file *orig = data->orig;
        return orig->f_op->remap_file_range(file_in, pos_in, orig, pos_out, len, remap_flags);
    } else {
        struct ksu_file_wrapper *data = file_in->private_data;
        struct file *orig = data->orig;
        return orig->f_op->remap_file_range(orig, pos_in, file_out, pos_out, len, remap_flags);
    }
}
#endif
"""

ANON_OLD = """    error = security_inode_init_security_anon(inode, &qname, context_inode);
"""

ANON_NEW = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    error = security_inode_init_security_anon(inode, &qname, context_inode);
#else
    (void)qname;
    (void)context_inode;
    error = 0;
#endif
"""

REPLACEMENTS = [
    (IOPOLL_OLD, IOPOLL_NEW, "iopoll wrappers"),
    (
        "    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;\n",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)\n"
        "    p->ops.iopoll = fp->f_op->iopoll ? ksu_wrapper_iopoll : NULL;\n"
        "#endif\n",
        "iopoll assignment",
    ),
    (REMAP_OLD, REMAP_NEW, "remap_file_range wrapper"),
    (
        "    p->ops.remap_file_range = fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;\n",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)\n"
        "    p->ops.remap_file_range = fp->f_op->remap_file_range ? ksu_wrapper_remap_file_range : NULL;\n"
        "#endif\n",
        "remap_file_range assignment",
    ),
    (ANON_OLD, ANON_NEW, "security_inode_init_security_anon"),
]


OPS_OLD = """static const struct fsnotify_ops ksu_ops = {
    .handle_inode_event = ksu_handle_inode_event,
};
"""

OPS_NEW = """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
static const struct fsnotify_ops ksu_ops = {
    .handle_inode_event = ksu_handle_inode_event,
};
#else
static int ksu_handle_event(struct fsnotify_group *group, struct inode *inode, u32 mask, const void *data,
                            int data_type, const unsigned char *file_name, u32 cookie,
                            struct fsnotify_iter_info *iter_info)
{
    struct qstr name;

    (void)group;
    (void)data;
    (void)data_type;
    (void)iter_info;
    if (!file_name)
        return ksu_handle_inode_event(NULL, mask, inode, inode, NULL, cookie);
    name.name = file_name;
    name.len = strlen(file_name);
    name.hash = 0;
    return ksu_handle_inode_event(NULL, mask, inode, inode, &name, cookie);
}

static const struct fsnotify_ops ksu_ops = {
    .handle_event = ksu_handle_event,
};
#endif
"""


SEPOLICY_H_OLD = """#include "ss/policydb.h"

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol);
"""

SEPOLICY_H_NEW = """#include "ss/policydb.h"
#include <linux/mutex.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
#include "ss/services.h"

struct selinux_policy {
    struct sidtab *sidtab;
    struct policydb policydb;
    struct selinux_map map;
    u32 latest_granting;
};

extern struct mutex ksu_selinux_policy_mutex;
struct selinux_policy *ksu_snapshot_selinux_policy(void);
int ksu_commit_selinux_policy(struct selinux_policy *pol);
struct selinux_policy *ksu_live_selinux_policy(struct selinux_policy *storage);
void ksu_free_selinux_policy_view(struct selinux_policy *pol);
#endif

struct selinux_policy *ksu_dup_sepolicy(struct selinux_policy *old_pol);
"""

ALIOTH_RULES_FN_OLD = """void apply_kernelsu_rules()
{
    struct selinux_policy *pol, *old_pol;
    struct policydb *db;
"""

ALIOTH_RULES_FN_NEW = """static void ksu_apply_alioth_compat_rules(struct policydb *db)
{
    static const char *const apps[] = {
        "untrusted_app", "untrusted_app_25", "untrusted_app_27",
        "untrusted_app_30", "untrusted_app_32",
    };
    static const char *const file_perms[] = {
        "execute", "execute_no_trans", "entrypoint",
        "getattr", "open", "read", "map",
    };
    static const char *const exec_tgts[] = {
        "shell_exec", "apk_data_file", "untrusted_app_lib_file", "app_data_file",
    };
    unsigned int i, j, k;

    pr_info("ksu: alioth HyperOS manager/enabler sepolicy\\n");
    for (i = 0; i < (unsigned int)(sizeof(apps) / sizeof(apps[0])); i++) {
        ksu_allow(db, apps[i], apps[i], "process2", "nosuid_transition");
        ksu_allow(db, apps[i], apps[i], "process", "transition");
        for (j = 0; j < (unsigned int)(sizeof(exec_tgts) / sizeof(exec_tgts[0])); j++) {
            for (k = 0; k < (unsigned int)(sizeof(file_perms) / sizeof(file_perms[0])); k++)
                ksu_allow(db, apps[i], exec_tgts[j], "file", file_perms[k]);
        }
        ksu_dontaudit(db, apps[i], KERNEL_SU_DOMAIN, ALL, ALL);
        ksu_dontaudit(db, apps[i], KERNEL_SU_FILE, ALL, ALL);
    }
    ksu_dontaudit(db, "priv_app", KERNEL_SU_DOMAIN, ALL, ALL);
    ksu_dontaudit(db, "priv_app", KERNEL_SU_FILE, ALL, ALL);
    ksu_dontaudit(db, "isolated_app", KERNEL_SU_DOMAIN, ALL, ALL);
    ksu_dontaudit(db, "isolated_app", KERNEL_SU_FILE, ALL, ALL);

    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "dir", "search");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "dir", "read");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "dir", "open");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "dir", "getattr");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "dir", "watch");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "dir", "watch_reads");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "file", "read");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "file", "open");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "file", "getattr");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "lnk_file", "read");
    ksu_allow(db, "vendor_feature_enabler_client", "mnt_vendor_file", "lnk_file", "getattr");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "dir", "search");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "dir", "read");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "dir", "open");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "dir", "getattr");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "file", "read");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "file", "open");
    ksu_allow(db, "vendor_feature_enabler_client", "vendor_persist_data_file", "file", "getattr");
}

void apply_kernelsu_rules()
{
    struct selinux_policy *pol, *old_pol;
    struct policydb *db;
"""

ALIOTH_RULES_CALL_OLD = """    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

    rcu_assign_pointer(selinux_state.policy, pol);
"""

ALIOTH_RULES_CALL_NEW = """    ksu_allow(db, "system_server", KERNEL_SU_DOMAIN, "process", "sigkill");

    ksu_apply_alioth_compat_rules(db);

    rcu_assign_pointer(selinux_state.policy, pol);
"""

RULES_REPLACEMENTS = [
    (ALIOTH_RULES_FN_OLD, ALIOTH_RULES_FN_NEW, "alioth manager/enabler sepolicy helper"),
    (ALIOTH_RULES_CALL_OLD, ALIOTH_RULES_CALL_NEW, "alioth sepolicy call"),
    (
        "    mutex_lock(&selinux_state.policy_mutex);\n\n    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));\n    backup_sepolicy = ksu_dup_sepolicy(old_pol);",
        "    mutex_lock(&ksu_selinux_policy_mutex);\n\n    old_pol = ksu_snapshot_selinux_policy();\n    if (IS_ERR(old_pol)) {\n        pr_err(\"snapshot sepolicy: %ld\\n\", PTR_ERR(old_pol));\n        mutex_unlock(&ksu_selinux_policy_mutex);\n        return;\n    }\n    backup_sepolicy = ksu_dup_sepolicy(old_pol);",
        "apply_kernelsu_rules snapshot",
    ),
    (
        "    rcu_assign_pointer(selinux_state.policy, pol);\n    synchronize_rcu();\n    ksu_destroy_sepolicy(old_pol);\n\n    reset_avc_cache(pol->latest_granting);\nout_unlock:\n    mutex_unlock(&selinux_state.policy_mutex);\n}",
        "    ksu_commit_selinux_policy(pol);\n    synchronize_rcu();\n    ksu_destroy_sepolicy(old_pol);\n    old_pol = NULL;\n    reset_avc_cache(pol->latest_granting);\n    kfree(pol);\nout_unlock:\n    mutex_unlock(&ksu_selinux_policy_mutex);\n    ksu_free_selinux_policy_view(old_pol);\n}",
        "apply_kernelsu_rules commit",
    ),
    (
        "    mutex_lock(&selinux_state.policy_mutex);\n\n    old_pol = rcu_dereference_protected(selinux_state.policy, lockdep_is_held(&selinux_state.policy_mutex));\n    pol = ksu_dup_sepolicy(old_pol);",
        "    mutex_lock(&ksu_selinux_policy_mutex);\n\n    old_pol = ksu_snapshot_selinux_policy();\n    if (IS_ERR(old_pol)) {\n        ret = PTR_ERR(old_pol);\n        old_pol = NULL;\n        goto out_unlock;\n    }\n    pol = ksu_dup_sepolicy(old_pol);",
        "handle_sepolicy snapshot",
    ),
    (
        "    rcu_assign_pointer(selinux_state.policy, pol);\n    synchronize_rcu();\n    ksu_destroy_sepolicy(old_pol);\n\n    reset_avc_cache(pol->latest_granting);\n    ret = success_cmd_count;\n    goto out_unlock;\n\nout_drop_new_policy:\n    ksu_destroy_sepolicy(pol);\nout_unlock:\n    mutex_unlock(&selinux_state.policy_mutex);",
        "    ksu_commit_selinux_policy(pol);\n    synchronize_rcu();\n    ksu_destroy_sepolicy(old_pol);\n    old_pol = NULL;\n    reset_avc_cache(pol->latest_granting);\n    kfree(pol);\n    ret = success_cmd_count;\n    goto out_unlock;\n\nout_drop_new_policy:\n    ksu_destroy_sepolicy(pol);\nout_unlock:\n    mutex_unlock(&ksu_selinux_policy_mutex);\n    ksu_free_selinux_policy_view(old_pol);",
        "handle_sepolicy commit",
    ),
]

APP_PROFILE_REPLACEMENTS = [
    (
        "    current->seccomp.mode = 0;\n    current->seccomp.filter = NULL;\n    atomic_set(&current->seccomp.filter_count, 0);",
        "    current->seccomp.mode = 0;\n    current->seccomp.filter = NULL;\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)\n    atomic_set(&current->seccomp.filter_count, 0);\n#endif",
        "seccomp filter_count",
    ),
    (
        "    seccomp_filter_release(fake);\n    kfree(fake);",
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)\n    seccomp_filter_release(fake);\n#else\n    put_seccomp_filter(fake);\n#endif\n    kfree(fake);",
        "seccomp_filter_release",
    ),
]

SECCOMP_CACHE_REPLACEMENTS = [
    (
        "void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)\n{\n    if (!filter) {\n        return;\n    }",
        "void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)\n{\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)\n    return;\n#endif\n    if (!filter) {\n        return;\n    }",
        "seccomp clear cache",
    ),
    (
        "void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)\n{\n    if (!filter) {\n        return;\n    }",
        "void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)\n{\n#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)\n    return;\n#endif\n    if (!filter) {\n        return;\n    }",
        "seccomp allow cache",
    ),
]

SEPOLICY_C_REPLACEMENTS = [
    (
        '#include <linux/vmalloc.h>\n',
        '#include <linux/vmalloc.h>\n#include <linux/flex_array.h>\n',
        "flex_array include",
    ),
    (
        "    struct class_datum *cls;\n    struct filename_trans_key *new_key = NULL;\n    int rc;\n",
        "    struct class_datum *cls;\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)\n    struct filename_trans_key *new_key = NULL;\n    int rc;\n#endif\n",
        "filename_trans decls",
    ),
    (
        "#define avtab_for_each(avtab, cur) ksu_hash_for_each(avtab.htable, avtab.nslot, cur)",
        """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define avtab_for_each(avtab, cur)                                                                             \\
    int i;                                                                                                     \\
    for (i = 0; i < (avtab).nslot; ++i)                                                                        \\
        for (cur = flex_array_get_ptr((avtab).htable, i); cur; cur = cur->next)
#else
#define avtab_for_each(avtab, cur) ksu_hash_for_each(avtab.htable, avtab.nslot, cur)
#endif""",
        "avtab_for_each flex_array",
    ),
    (
        """    for (i = 0; i < db->te_avtab.nslot; i++) {
        prev = NULL;
        for (n = db->te_avtab.htable[i]; n; prev = n, n = n->next) {
            if (n != node)
                continue;

            if (prev)
                prev->next = n->next;
            else
                db->te_avtab.htable[i] = n->next;

            if (db->te_avtab.nel > 0)
                db->te_avtab.nel--;

            if (n->key.specified & AVTAB_XPERMS)
                // specified and driver are u8, perms.p holds 8 u32s
                shrink_size += sizeof(n->datum.u.xperms->specified) + sizeof(n->datum.u.xperms->driver) +
                               sizeof(n->datum.u.xperms->perms.p);
            else
                // data is u32
                shrink_size += sizeof(n->datum.u.data);
            n->next = NULL;
            removed.htable[0] = n;
            removed.nel = 1;""",
        """    for (i = 0; i < db->te_avtab.nslot; i++) {
        prev = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
        for (n = flex_array_get_ptr(db->te_avtab.htable, i); n; prev = n, n = n->next)
#else
        for (n = db->te_avtab.htable[i]; n; prev = n, n = n->next)
#endif
        {
            if (n != node)
                continue;

            if (prev)
                prev->next = n->next;
            else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
                flex_array_put_ptr(db->te_avtab.htable, i, n->next, GFP_ATOMIC);
#else
                db->te_avtab.htable[i] = n->next;
#endif
            }

            if (db->te_avtab.nel > 0)
                db->te_avtab.nel--;

            if (n->key.specified & AVTAB_XPERMS)
                // specified and driver are u8, perms.p holds 8 u32s
                shrink_size += sizeof(n->datum.u.xperms->specified) + sizeof(n->datum.u.xperms->driver) +
                               sizeof(n->datum.u.xperms->perms.p);
            else
                // data is u32
                shrink_size += sizeof(n->datum.u.data);
            n->next = NULL;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
            flex_array_put_ptr(removed.htable, 0, n, GFP_ATOMIC);
#else
            removed.htable[0] = n;
#endif
            removed.nel = 1;""",
        "remove_avtab_node flex_array",
    ),
    (
        """    struct filename_trans_key key;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = (char *)o;

    struct filename_trans_datum *last = NULL;

    struct filename_trans_datum *trans = policydb_filenametr_search(db, &key);""",
        """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
    struct filename_trans key;
    struct filename_trans *new_ft;
    struct filename_trans_datum *trans;

    key.stype = src->value;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = o;
    trans = hashtab_search(db->filename_trans, &key);
    if (trans) {
        trans->otype = def->value;
        return ebitmap_set_bit(&db->filename_trans_ttypes, src->value - 1, 1) == 0;
    }
    trans = kzalloc(sizeof(*trans), GFP_KERNEL);
    new_ft = kzalloc(sizeof(*new_ft), GFP_KERNEL);
    if (!trans || !new_ft) {
        kfree(trans);
        kfree(new_ft);
        return false;
    }
    *new_ft = key;
    new_ft->name = kstrdup(o, GFP_KERNEL);
    trans->otype = def->value;
    if (!new_ft->name || hashtab_insert(db->filename_trans, new_ft, trans)) {
        kfree((void *)new_ft->name);
        kfree(new_ft);
        kfree(trans);
        return false;
    }
    return ebitmap_set_bit(&db->filename_trans_ttypes, src->value - 1, 1) == 0;
#else
    struct filename_trans_key key;
    key.ttype = tgt->value;
    key.tclass = cls->value;
    key.name = (char *)o;

    struct filename_trans_datum *last = NULL;

    struct filename_trans_datum *trans = policydb_filenametr_search(db, &key);""",
        "add_filename_trans 4.19",
    ),
    (
        """out:
    return false;
}

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context)""",
        """out:
    return false;
#endif
}

static bool add_genfscon(struct policydb *db, const char *fs_name, const char *path, const char *context)""",
        "add_filename_trans endif",
    ),
    (
        """    struct ebitmap *new_type_attr_map_array =
        ksu_kvrealloc(db->type_attr_map_array, value * sizeof(struct ebitmap), (value - 1) * sizeof(struct ebitmap));

    if (!new_type_attr_map_array) {
        pr_err("add_type: alloc type_attr_map_array failed\\n");
        return false;
    }

    struct type_datum **new_type_val_to_struct = ksu_kvrealloc(
        db->type_val_to_struct, sizeof(*db->type_val_to_struct) * value, sizeof(*db->type_val_to_struct) * (value - 1));

    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\\n");
        return false;
    }

    char **new_val_to_name_types =
        ksu_kvrealloc(db->sym_val_to_name[SYM_TYPES], sizeof(char *) * value, sizeof(char *) * (value - 1));
    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\\n");
        return false;
    }

    db->type_attr_map_array = new_type_attr_map_array;
    ebitmap_init(&db->type_attr_map_array[value - 1]);
    ebitmap_set_bit(&db->type_attr_map_array[value - 1], value - 1, 1);

    db->type_val_to_struct = new_type_val_to_struct;
    db->type_val_to_struct[value - 1] = type;

    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    db->sym_val_to_name[SYM_TYPES][value - 1] = key;

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);
    }

    return true;
}""",
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    struct ebitmap *new_type_attr_map_array =
        ksu_kvrealloc(db->type_attr_map_array, value * sizeof(struct ebitmap), (value - 1) * sizeof(struct ebitmap));

    if (!new_type_attr_map_array) {
        pr_err("add_type: alloc type_attr_map_array failed\\n");
        return false;
    }

    struct type_datum **new_type_val_to_struct = ksu_kvrealloc(
        db->type_val_to_struct, sizeof(*db->type_val_to_struct) * value, sizeof(*db->type_val_to_struct) * (value - 1));

    if (!new_type_val_to_struct) {
        pr_err("add_type: alloc type_val_to_struct failed\\n");
        return false;
    }

    char **new_val_to_name_types =
        ksu_kvrealloc(db->sym_val_to_name[SYM_TYPES], sizeof(char *) * value, sizeof(char *) * (value - 1));
    if (!new_val_to_name_types) {
        pr_err("add_type: alloc val_to_name failed\\n");
        return false;
    }

    db->type_attr_map_array = new_type_attr_map_array;
    ebitmap_init(&db->type_attr_map_array[value - 1]);
    ebitmap_set_bit(&db->type_attr_map_array[value - 1], value - 1, 1);

    db->type_val_to_struct = new_type_val_to_struct;
    db->type_val_to_struct[value - 1] = type;

    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    db->sym_val_to_name[SYM_TYPES][value - 1] = key;
#else
    struct flex_array *new_type_attr_map_array =
        flex_array_alloc(sizeof(struct ebitmap), db->p_types.nprim, GFP_KERNEL | __GFP_ZERO);
    struct flex_array *new_type_val_to_struct =
        flex_array_alloc(sizeof(struct type_datum *), db->p_types.nprim, GFP_KERNEL | __GFP_ZERO);
    struct flex_array *new_val_to_name_types =
        flex_array_alloc(sizeof(char *), db->p_types.nprim, GFP_KERNEL | __GFP_ZERO);
    struct flex_array *old_fa;
    void *old_elem;
    int j;

    if (!new_type_attr_map_array || !new_type_val_to_struct || !new_val_to_name_types)
        return false;
    if (flex_array_prealloc(new_type_attr_map_array, 0, db->p_types.nprim, GFP_KERNEL | __GFP_ZERO) ||
        flex_array_prealloc(new_type_val_to_struct, 0, db->p_types.nprim, GFP_KERNEL | __GFP_ZERO) ||
        flex_array_prealloc(new_val_to_name_types, 0, db->p_types.nprim, GFP_KERNEL | __GFP_ZERO))
        return false;
    for (j = 0; j < db->type_attr_map_array->total_nr_elements; j++) {
        old_elem = flex_array_get(db->type_attr_map_array, j);
        if (old_elem)
            flex_array_put(new_type_attr_map_array, j, old_elem, GFP_KERNEL | __GFP_ZERO);
    }
    for (j = 0; j < db->type_val_to_struct_array->total_nr_elements; j++) {
        old_elem = flex_array_get_ptr(db->type_val_to_struct_array, j);
        if (old_elem)
            flex_array_put_ptr(new_type_val_to_struct, j, old_elem, GFP_KERNEL | __GFP_ZERO);
    }
    for (j = 0; j < value - 1; j++) {
        old_elem = flex_array_get_ptr(db->sym_val_to_name[SYM_TYPES], j);
        if (old_elem)
            flex_array_put_ptr(new_val_to_name_types, j, old_elem, GFP_KERNEL | __GFP_ZERO);
    }
    old_fa = db->type_attr_map_array;
    db->type_attr_map_array = new_type_attr_map_array;
    if (old_fa)
        flex_array_free(old_fa);
    ebitmap_init(flex_array_get(db->type_attr_map_array, value - 1));
    ebitmap_set_bit(flex_array_get(db->type_attr_map_array, value - 1), value - 1, 1);
    old_fa = db->type_val_to_struct_array;
    db->type_val_to_struct_array = new_type_val_to_struct;
    if (old_fa)
        flex_array_free(old_fa);
    flex_array_put_ptr(db->type_val_to_struct_array, value - 1, type, GFP_KERNEL | __GFP_ZERO);
    old_fa = db->sym_val_to_name[SYM_TYPES];
    db->sym_val_to_name[SYM_TYPES] = new_val_to_name_types;
    if (old_fa)
        flex_array_free(old_fa);
    flex_array_put_ptr(db->sym_val_to_name[SYM_TYPES], value - 1, key, GFP_KERNEL | __GFP_ZERO);
#endif

    int i;
    for (i = 0; i < db->p_roles.nprim; ++i) {
        ebitmap_set_bit(&db->role_val_to_struct[i]->types, value - 1, 1);
    }

    return true;
}""",
        "add_type flex_array",
    ),
    (
        "    struct ebitmap *sattr = &db->type_attr_map_array[type->value - 1];",
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    struct ebitmap *sattr = &db->type_attr_map_array[type->value - 1];
#else
    struct ebitmap *sattr = flex_array_get(db->type_attr_map_array, type->value - 1);
#endif""",
        "add_typeattribute_raw flex_array",
    ),
]

HIDE_SEPOLICY_REPLACEMENTS = [
    (
        "#include <linux/mutex.h>\n",
        "#include <linux/mutex.h>\n#include <linux/flex_array.h>\n",
        "hide flex_array include",
    ),
    (
        "static DEFINE_MUTEX(selinux_hide_mutex);\n",
        """#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#define symtab_search(s, name) hashtab_search((s)->table, name)
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#define ksu_type_datum(p, idx) ((struct type_datum *)flex_array_get_ptr((p)->type_val_to_struct_array, (idx)))
#define ksu_type_attr_map(p, idx) ((struct ebitmap *)flex_array_get((p)->type_attr_map_array, (idx)))
#else
#define ksu_type_datum(p, idx) ((p)->type_val_to_struct[(idx)])
#define ksu_type_attr_map(p, idx) (&(p)->type_attr_map_array[(idx)])
#endif

static DEFINE_MUTEX(selinux_hide_mutex);
""",
        "hide type/symtab macros",
    ),
    (
        """static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,
                                  char **scontext, u32 *scontext_len)
{
    int rc = sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);

    if (rc != -ENOENT)
        return rc;

    rc = context_struct_to_string(p, &entry->context, scontext, scontext_len);
    if (!rc && scontext)
        sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}

static int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext,
                                               u32 *scontext_len)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    struct sidtab_entry *entry;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    // removed: if (!selinux_initialized())
    // removed: rcu lock
    policydb = &policy->policydb;
    sidtab = policy->sidtab;

    // removed: force
    entry = sidtab_search_entry(sidtab, sid);
    if (!entry) {
        pr_err("SELinux: %s:  unrecognized SID %d\\n", __func__, sid);
        rc = -EINVAL;
        goto out_unlock;
    }
    // removed: only_invalid

    rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);

out_unlock:
    return rc;
}
""",
        """#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
static int sidtab_entry_to_string(struct policydb *p, struct sidtab *sidtab, struct sidtab_entry *entry,
                                  char **scontext, u32 *scontext_len)
{
    int rc = sidtab_sid2str_get(sidtab, entry, scontext, scontext_len);

    if (rc != -ENOENT)
        return rc;

    rc = context_struct_to_string(p, &entry->context, scontext, scontext_len);
    if (!rc && scontext)
        sidtab_sid2str_put(sidtab, entry, *scontext, *scontext_len);
    return rc;
}
#endif

static int security_sid_to_context_with_policy(struct selinux_policy *policy, u32 sid, char **scontext,
                                               u32 *scontext_len)
{
    struct policydb *policydb;
    struct sidtab *sidtab;
    int rc = 0;

    if (scontext)
        *scontext = NULL;
    *scontext_len = 0;

    policydb = &policy->policydb;
    sidtab = policy->sidtab;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    {
        struct sidtab_entry *entry = sidtab_search_entry(sidtab, sid);
        if (!entry) {
            pr_err("SELinux: %s:  unrecognized SID %d\\n", __func__, sid);
            rc = -EINVAL;
            goto out_unlock;
        }
        rc = sidtab_entry_to_string(policydb, sidtab, entry, scontext, scontext_len);
    }
#else
    {
        struct context *ctx = sidtab_search(sidtab, sid);
        if (!ctx) {
            pr_err("SELinux: %s:  unrecognized SID %d\\n", __func__, sid);
            rc = -EINVAL;
            goto out_unlock;
        }
        rc = context_struct_to_string(policydb, ctx, scontext, scontext_len);
    }
#endif

out_unlock:
    return rc;
}
""",
        "hide sidtab 4.19",
    ),
    (
        "    source = policydb->type_val_to_struct[scontext->type - 1];",
        "    source = ksu_type_datum(policydb, scontext->type - 1);",
        "hide type_val source",
    ),
    (
        "    target = policydb->type_val_to_struct[tcontext->type - 1];",
        "    target = ksu_type_datum(policydb, tcontext->type - 1);",
        "hide type_val target",
    ),
    (
        "    sattr = &policydb->type_attr_map_array[scontext->type - 1];\n    tattr = &policydb->type_attr_map_array[tcontext->type - 1];",
        "    sattr = ksu_type_attr_map(policydb, scontext->type - 1);\n    tattr = ksu_type_attr_map(policydb, tcontext->type - 1);",
        "hide type_attr_map",
    ),
]

HIDE_REPLACEMENTS = [
    (
        "    struct selinux_policy *orig_policy;\n    struct policydb *policydb, *orig_policydb;",
        "    struct selinux_policy *orig_policy;\n    struct selinux_policy ksu_live_pol;\n    struct policydb *policydb, *orig_policydb;",
        "hide orig_policy storage",
    ),
    (
        "    orig_policy = rcu_dereference(selinux_state.policy);",
        "    orig_policy = ksu_live_selinux_policy(&ksu_live_pol);",
        "hide orig_policy live",
    ),
    (
        "    struct selinux_policy *policy;\n    struct context context;",
        "    struct selinux_policy *policy;\n    struct selinux_policy ksu_live_pol;\n    struct context context;",
        "hide policy storage",
    ),
    (
        "    policy = rcu_dereference(selinux_state.policy);",
        "    policy = ksu_live_selinux_policy(&ksu_live_pol);",
        "hide policy live",
    ),
]


# 4.19 Qualcomm maps the kernel image with PMD sections (pmd_leaf is 5.13+).
# phys_from_virt then fails, ksu_patch_text returns -ENOENT, but 3.x still
# sets ksu_dispatcher_nr and sys_enter redirects execve to an unpatched
# ni_syscall slot — init cannot exec, device drops back to fastboot.
PATCH_MEMORY_INCLUDES_OLD = '#include "asm-generic/fixmap.h"\n'
PATCH_MEMORY_INCLUDES_NEW = """#include "asm-generic/fixmap.h"
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/memory.h>
#include <asm/sections.h>
"""

PHYS_FROM_VIRT_OLD = """    *err = 0;

    pgd = pgd_offset(mm, addr);
"""
PHYS_FROM_VIRT_NEW = """    *err = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
    /* arm64 KASLR puts .rodata (sys_call_table) in the kimage map.
     * virt_to_phys() uses the linear map and pokes the wrong page. */
    if (addr >= (unsigned long)_text && addr < (unsigned long)_end)
        return __pa_symbol(addr);
#endif

    pgd = pgd_offset(mm, addr);
"""

PMD_LEAF_OLD = """    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd)) {
        return __pmd_to_phys(*pmd) + ((addr & ~PMD_MASK));
    }
#endif
"""
PMD_LEAF_NEW = """    pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd)) {
        return __pmd_to_phys(*pmd) + ((addr & ~PMD_MASK));
    }
#elif defined(pmd_sect)
    if (pmd_sect(*pmd))
        return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
"""

COPY_NOFAULT_OLD = """    void *map = set_fixmap_offset(FIX_TEXT_POKE0, phy);

    ret = (int)copy_to_kernel_nofault(map, src, len);

    clear_fixmap(FIX_TEXT_POKE0);
"""
COPY_NOFAULT_NEW = """    void *map = set_fixmap_offset(FIX_TEXT_POKE0, phy);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
    memcpy(map, src, len);
    ret = 0;
#else
    ret = (int)copy_to_kernel_nofault(map, src, len);
#endif

    clear_fixmap(FIX_TEXT_POKE0);
"""

DISPATCHER_OLD = """    ksu_dispatcher_nr = ni_slot;
    ksu_syscall_table_hook(ksu_dispatcher_nr, (syscall_fn_t)ksu_syscall_dispatcher, NULL);
    pr_info("dispatcher installed at slot %d\\n", ksu_dispatcher_nr);
"""
DISPATCHER_NEW = """    {
        syscall_fn_t orig = READ_ONCE(ksu_syscall_table[ni_slot]);
        if (patch_syscall_table(ni_slot, (syscall_fn_t)ksu_syscall_dispatcher)) {
            pr_err("dispatcher patch failed at slot %d, not enabling sys_enter redirect\\n", ni_slot);
            return;
        }
        mutex_lock(&hooked_entries_lock);
        if (hooked_count < ARRAY_SIZE(hooked_entries)) {
            hooked_entries[hooked_count].nr = ni_slot;
            hooked_entries[hooked_count].orig = orig;
            hooked_count++;
        }
        mutex_unlock(&hooked_entries_lock);
        if (READ_ONCE(ksu_syscall_table[ni_slot]) != (syscall_fn_t)ksu_syscall_dispatcher) {
            pr_err("dispatcher patch did not stick at slot %d (got 0x%lx)\\n", ni_slot,
                   (unsigned long)READ_ONCE(ksu_syscall_table[ni_slot]));
            return;
        }
        ksu_dispatcher_nr = ni_slot;
        pr_info("dispatcher installed at slot %d\\n", ksu_dispatcher_nr);
    }
"""

SYS_ENTER_OLD = """#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_prio_sys_enter(ksu_sys_enter_handler, NULL, INT_MIN);
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\\n");
    }
#endif
"""
SYS_ENTER_NEW = """#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    if (ksu_dispatcher_nr < 0) {
        pr_err("hook_manager: no dispatcher slot, skip sys_enter (boot-safe)\\n");
        ret = -ENODEV;
    } else {
        ret = register_trace_prio_sys_enter(ksu_sys_enter_handler, NULL, INT_MIN);
    }
#ifndef CONFIG_KRETPROBES
    ksu_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\\n");
    }
#endif
    ksu_kprobe_fallback_init();
"""

HOOK_MGR_INCLUDE_OLD = '#include "hook/syscall_event_bridge.h"\n'
HOOK_MGR_INCLUDE_NEW = '#include "hook/syscall_event_bridge.h"\n#include "hook/kprobe_fallback.h"\n'

HOOK_MGR_EXIT_OLD = """    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
"""
HOOK_MGR_EXIT_NEW = """    ksu_kprobe_fallback_exit();
    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
}
"""

BOOT_EVENT_OLD = """    ksu_selinux_hide_handle_post_fs_data();
    // retry forced features which failed at second stage
    ksu_feature_apply_forced();
}
"""
BOOT_EVENT_NEW = """    ksu_selinux_hide_handle_post_fs_data();
    // retry forced features which failed at second stage
    ksu_feature_apply_forced();
    track_throne(false);
}
"""


def apply_replacements(path: Path, replacements, already_marker: str, label: str, replace_all: bool = False) -> None:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if already_marker and already_marker in text:
        print(f"already patched: {path}")
        return
    for old, new, item in replacements:
        if old not in text:
            sys.exit(f"4.19 compat: missing marker for {item} in {path}")
        text = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    path.write_text(text, encoding="utf-8", newline="\n")
    print(f"patched 4.19 {label}: {path}")


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("usage: patch_ksu_419.py <KernelSU/kernel>")
    kernel_dir = Path(sys.argv[1])
    wrapper = kernel_dir / "infra" / "file_wrapper.c"
    observer = kernel_dir / "manager" / "pkg_observer.c"
    sepolicy_h = kernel_dir / "selinux" / "sepolicy.h"
    rules = kernel_dir / "selinux" / "rules.c"
    hide = kernel_dir / "feature" / "selinux_hide.c"
    if not wrapper.is_file():
        sys.exit(f"4.19 compat: {wrapper} not found")
    apply_replacements(wrapper, REPLACEMENTS, "LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)\n#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)", "file_ops")
    if observer.is_file():
        apply_replacements(observer, [(OPS_OLD, OPS_NEW, "fsnotify handle_inode_event")], "ksu_handle_event", "pkg_observer")
    if sepolicy_h.is_file():
        apply_replacements(sepolicy_h, [(SEPOLICY_H_OLD, SEPOLICY_H_NEW, "selinux_policy struct")], "ksu_snapshot_selinux_policy", "sepolicy.h")
    if rules.is_file():
        apply_replacements(rules, RULES_REPLACEMENTS, "ksu_snapshot_selinux_policy", "rules.c")
    if hide.is_file():
        apply_replacements(hide, HIDE_REPLACEMENTS, "ksu_live_selinux_policy", "selinux_hide.c")
        apply_replacements(hide, HIDE_SEPOLICY_REPLACEMENTS, "ksu_type_datum", "selinux_hide sepolicy")
        hide_text = hide.read_text(encoding="utf-8").replace("\r\n", "\n")
        hide_text = hide_text.replace("selinux_state.status_lock", "selinux_state.ss->status_lock")
        hide_text = hide_text.replace("selinux_state.status_page", "selinux_state.ss->status_page")
        hide.write_text(hide_text, encoding="utf-8", newline="\n")
        print(f"patched 4.19 selinux_hide status_*: {hide}")
    app_profile = kernel_dir / "policy" / "app_profile.c"
    if app_profile.is_file():
        apply_replacements(app_profile, APP_PROFILE_REPLACEMENTS, "put_seccomp_filter(fake)", "app_profile.c")
    seccomp_cache = kernel_dir / "infra" / "seccomp_cache.c"
    if seccomp_cache.is_file():
        apply_replacements(seccomp_cache, SECCOMP_CACHE_REPLACEMENTS, "LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)", "seccomp_cache.c")
    sepolicy_c = kernel_dir / "selinux" / "sepolicy.c"
    if sepolicy_c.is_file():
        apply_replacements(sepolicy_c, SEPOLICY_C_REPLACEMENTS, "flex_array_get_ptr((avtab).htable, i)", "sepolicy.c")
    patch_mem = kernel_dir / "hook" / "arm64" / "patch_memory.c"
    if patch_mem.is_file():
        apply_replacements(
            patch_mem,
            [
                (PATCH_MEMORY_INCLUDES_OLD, PATCH_MEMORY_INCLUDES_NEW, "patch_memory includes"),
                (PHYS_FROM_VIRT_OLD, PHYS_FROM_VIRT_NEW, "phys_from_virt kimage"),
                (PMD_LEAF_OLD, PMD_LEAF_NEW, "pmd_sect"),
                (COPY_NOFAULT_OLD, COPY_NOFAULT_NEW, "fixmap memcpy"),
            ],
            "__pa_symbol(addr)",
            "arm64 patch_memory.c",
        )
    syscall_hook = kernel_dir / "hook" / "arm64" / "syscall_hook.c"
    if syscall_hook.is_file():
        apply_replacements(
            syscall_hook,
            [(DISPATCHER_OLD, DISPATCHER_NEW, "dispatcher install")],
            "dispatcher patch did not stick",
            "arm64 syscall_hook.c",
        )
    hook_mgr = kernel_dir / "hook" / "syscall_hook_manager.c"
    if hook_mgr.is_file():
        apply_replacements(
            hook_mgr,
            [
                (HOOK_MGR_INCLUDE_OLD, HOOK_MGR_INCLUDE_NEW, "kprobe_fallback include"),
                (SYS_ENTER_OLD, SYS_ENTER_NEW, "sys_enter guard"),
                (HOOK_MGR_EXIT_OLD, HOOK_MGR_EXIT_NEW, "kprobe_fallback exit"),
            ],
            "ksu_kprobe_fallback_init",
            "syscall_hook_manager.c",
        )
    boot_event = kernel_dir / "runtime" / "boot_event.c"
    if boot_event.is_file():
        apply_replacements(
            boot_event,
            [(BOOT_EVENT_OLD, BOOT_EVENT_NEW, "post_fs_data track_throne")],
            "track_throne(false);",
            "boot_event.c",
        )
    here = Path(__file__).resolve().parent
    fallback_c = here / "kprobe_fallback.c"
    fallback_h = here / "kprobe_fallback.h"
    if fallback_c.is_file() and fallback_h.is_file():
        dest_c = kernel_dir / "hook" / "kprobe_fallback.c"
        dest_h = kernel_dir / "hook" / "kprobe_fallback.h"
        dest_c.write_text(fallback_c.read_text(encoding="utf-8").replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        dest_h.write_text(fallback_h.read_text(encoding="utf-8").replace("\r\n", "\n"), encoding="utf-8", newline="\n")
        print(f"installed 4.19 kprobe_fallback: {dest_c}")
        kbuild = kernel_dir / "Kbuild"
        if kbuild.is_file():
            kb = kbuild.read_text(encoding="utf-8").replace("\r\n", "\n")
            if "hook/kprobe_fallback.o" not in kb:
                needle = "kernelsu-objs += hook/syscall_hook_manager.o\n"
                if needle not in kb:
                    sys.exit("4.19 compat: missing Kbuild marker for kprobe_fallback")
                kbuild.write_text(
                    kb.replace(needle, needle + "kernelsu-objs += hook/kprobe_fallback.o\n", 1),
                    encoding="utf-8",
                    newline="\n",
                )
                print(f"patched 4.19 Kbuild: {kbuild}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
