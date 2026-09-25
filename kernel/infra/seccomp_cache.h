#ifndef __KSU_H_SECCOMP_CACHE
#define __KSU_H_SECCOMP_CACHE

#include <linux/fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
/* Native and compat ABIs do not necessarily use the same syscall number.
 * Keep the two cache updates separate so a 32-bit manager running on an
 * arm64 kernel receives the compat syscall it actually invokes. */
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr);
extern void ksu_seccomp_allow_cache_compat(struct seccomp_filter *filter, int nr);
#endif

#endif
