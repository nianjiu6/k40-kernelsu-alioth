#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#include "security.h"
#include "selinux/sepolicy.h"
#include "ss/services.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)

DEFINE_MUTEX(ksu_selinux_policy_mutex);

struct selinux_policy *ksu_snapshot_selinux_policy(void)
{
	struct selinux_ss *ss = selinux_state.ss;
	struct selinux_policy *pol;

	if (!ss)
		return ERR_PTR(-EINVAL);

	pol = kzalloc(sizeof(*pol), GFP_KERNEL);
	if (!pol)
		return ERR_PTR(-ENOMEM);

	read_lock(&ss->policy_rwlock);
	pol->sidtab = ss->sidtab;
	pol->policydb = ss->policydb;
	pol->map = ss->map;
	pol->latest_granting = ss->latest_granting;
	read_unlock(&ss->policy_rwlock);
	return pol;
}

int ksu_commit_selinux_policy(struct selinux_policy *pol)
{
	struct selinux_ss *ss = selinux_state.ss;

	if (!ss || !pol)
		return -EINVAL;

	write_lock_irq(&ss->policy_rwlock);
	ss->policydb = pol->policydb;
	ss->latest_granting = pol->latest_granting;
	memset(&pol->policydb, 0, sizeof(pol->policydb));
	write_unlock_irq(&ss->policy_rwlock);
	return 0;
}

struct selinux_policy *ksu_live_selinux_policy(struct selinux_policy *storage)
{
	struct selinux_ss *ss = selinux_state.ss;

	if (!ss || !storage)
		return NULL;

	storage->sidtab = ss->sidtab;
	storage->policydb = ss->policydb;
	storage->map = ss->map;
	storage->latest_granting = ss->latest_granting;
	return storage;
}

void ksu_free_selinux_policy_view(struct selinux_policy *pol)
{
	kfree(pol);
}

#endif
