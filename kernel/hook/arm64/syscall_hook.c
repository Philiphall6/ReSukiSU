#ifdef __aarch64__

#include "../syscall_hook.h"

#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <asm/cacheflush.h>
#include <asm/unistd.h>
#include "infra/symbol_resolver.h"
#include "../patch_memory.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep

syscall_fn_t *ksu_syscall_table = NULL;
int ksu_dispatcher_nr = -1;

#ifdef CONFIG_COMPAT
syscall_fn_t *ksu_compat_syscall_table = NULL;
int ksu_compat_dispatcher_nr = -1;
#endif

// Hook registration table — read with READ_ONCE from tracepoint/dispatcher
// context, written with WRITE_ONCE from init/exit context.
static ksu_syscall_hook_fn syscall_hooks[__NR_syscalls];

#ifdef CONFIG_COMPAT
static ksu_syscall_hook_fn compat_syscall_hooks[__NR_compat_syscalls];
static syscall_fn_t compat_dispatcher_orig;
static bool compat_dispatcher_patched;
#endif

// Track all hooked syscall entries for restoration.
// Protected by hooked_entries_lock.
struct syscall_hook_entry {
    int nr;
    syscall_fn_t orig;
};

static DEFINE_MUTEX(hooked_entries_lock);
static struct syscall_hook_entry hooked_entries[16];
static int hooked_count = 0;

static int patch_syscall_table_entry(syscall_fn_t *table, int table_size, int nr, syscall_fn_t fn,
                                     const char *table_name)
{
    if (!table)
        return -ENOENT;
    if (nr < 0 || nr >= table_size)
        return -EINVAL;

    pr_info("patch %s syscall %d, 0x%lx -> 0x%lx\n", table_name, nr,
            (unsigned long)READ_ONCE(table[nr]), (unsigned long)fn);

    if (ksu_patch_text(&table[nr], &fn, sizeof(fn), KSU_PATCH_TEXT_FLUSH_DCACHE)) {
        pr_err("patch %s syscall %d failed\n", table_name, nr);
        return -EIO;
    }

    return 0;
}

static int patch_syscall_table(int nr, syscall_fn_t fn)
{
    return patch_syscall_table_entry(ksu_syscall_table, __NR_syscalls, nr, fn, "native");
}

#ifdef CONFIG_COMPAT
static int patch_compat_syscall_table(int nr, syscall_fn_t fn)
{
    return patch_syscall_table_entry(ksu_compat_syscall_table, __NR_compat_syscalls, nr, fn, "compat");
}
#endif

// Direct syscall table patching: overwrite syscall_table[nr] with fn,
// save original to *old, and record for restoration at module exit.
void ksu_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old)
{
    if (ksu_syscall_table == NULL)
        return;
    if (nr < 0 || nr >= __NR_syscalls) {
        pr_info("invalid nr: %d\n", nr);
        return;
    }

    mutex_lock(&hooked_entries_lock);

    syscall_fn_t orig = READ_ONCE(ksu_syscall_table[nr]);
    if (old)
        *old = orig;

    // Record for later restoration
    int i;
    bool found = false;
    for (i = 0; i < hooked_count; i++) {
        if (hooked_entries[i].nr == nr) {
            found = true;
            break;
        }
    }
    if (!found) {
        if (hooked_count < ARRAY_SIZE(hooked_entries)) {
            hooked_entries[hooked_count].nr = nr;
            hooked_entries[hooked_count].orig = orig;
            hooked_count++;
        } else {
            pr_warn("hooked_entries full, cannot track syscall %d for restoration\n", nr);
        }
    }

    patch_syscall_table(nr, fn);

    mutex_unlock(&hooked_entries_lock);
}

// Restore syscall_table[nr] to its original value and remove from tracking list.
void ksu_syscall_table_unhook(int nr)
{
    int i;

    if (ksu_syscall_table == NULL)
        return;
    if (nr < 0 || nr >= __NR_syscalls)
        return;

    mutex_lock(&hooked_entries_lock);

    for (i = 0; i < hooked_count; i++) {
        if (hooked_entries[i].nr == nr) {
            patch_syscall_table(nr, hooked_entries[i].orig);
            // Remove entry by swapping with last
            hooked_entries[i] = hooked_entries[--hooked_count];
            mutex_unlock(&hooked_entries_lock);
            pr_info("unhooked syscall %d\n", nr);
            return;
        }
    }

    mutex_unlock(&hooked_entries_lock);
    pr_warn("syscall %d not found in hooked entries\n", nr);
}

static int __init ksu_find_ni_syscall_slots(syscall_fn_t *table, int table_size, const char *table_name,
                                            int *out_slots, int max_slots)
{
    unsigned long ni_syscall;
    int i, count = 0;

    if (!table || table_size <= 0 || max_slots <= 0)
        return 0;

    ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook("__arm64_sys_ni_syscall");

    pr_info("sys_ni_syscall: 0x%lx\n", ni_syscall);

    if (!ni_syscall)
        return 0;

    for (i = 0; i < table_size && count < max_slots; i++) {
        if ((unsigned long)READ_ONCE(table[i]) == ni_syscall) {
            out_slots[count++] = i;
            pr_info("%s ni_syscall %d: %d\n", table_name, count, i);
        }
    }

    return count;
}

// Unified dispatcher: reads original NR from x8, dispatches to handler.
// Validates that syscallno matches our dispatcher slot (i.e. we redirected it),
// otherwise it's a spurious call — return -ENOSYS.
static long __nocfi ksu_syscall_dispatcher(const struct pt_regs *regs)
{
    if (regs->syscallno != ksu_dispatcher_nr)
        return -ENOSYS;

    int orig_nr = (int)PT_REGS_ORIG_SYSCALL(regs);

    if (regs->syscallno == orig_nr)
        return -ENOSYS;

    // Restore registers to original state before dispatching
    ((struct pt_regs *)regs)->syscallno = orig_nr;
    PT_REGS_ORIG_SYSCALL((struct pt_regs *)regs) = orig_nr;

    if (likely(orig_nr >= 0 && orig_nr < __NR_syscalls)) {
        ksu_syscall_hook_fn fn = READ_ONCE(syscall_hooks[orig_nr]);
        if (likely(fn))
            return fn(orig_nr, regs);
    }

    return -ENOSYS;
}

#ifdef CONFIG_COMPAT
/*
 * The AArch32 syscall number is supplied in r7.  syscall_trace_enter() uses
 * regs->syscallno as its return value, so the tracepoint can redirect only
 * that field while leaving r7 intact as the original routing key.
 */
static long __nocfi ksu_compat_syscall_dispatcher(const struct pt_regs *regs)
{
    int orig_nr;
    ksu_syscall_hook_fn fn;

    if (regs->syscallno != ksu_compat_dispatcher_nr)
        return -ENOSYS;

    orig_nr = (int)regs->regs[7];
    if (orig_nr == ksu_compat_dispatcher_nr || orig_nr < 0 || orig_nr >= __NR_compat_syscalls)
        return -ENOSYS;

    ((struct pt_regs *)regs)->syscallno = orig_nr;
    fn = READ_ONCE(compat_syscall_hooks[orig_nr]);
    if (likely(fn))
        return fn(orig_nr, regs);

    return -ENOSYS;
}
#endif

// Register a handler into the dispatcher's routing table.
// Does not modify the syscall table — the dispatcher slot is shared by all hooks.
int ksu_register_syscall_hook(int nr, ksu_syscall_hook_fn fn)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;
    if (READ_ONCE(syscall_hooks[nr])) {
        pr_warn("syscall hook for nr=%d already registered, skip\n", nr);
        return -EEXIST;
    }
    WRITE_ONCE(syscall_hooks[nr], fn);
    pr_info("registered syscall hook for nr=%d\n", nr);
    return 0;
}

// Remove a handler from the dispatcher's routing table.
// The syscall table is not touched — only the dispatcher stops routing this nr.
void ksu_unregister_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return;
    WRITE_ONCE(syscall_hooks[nr], NULL);
    pr_info("unregistered syscall hook for nr=%d\n", nr);
}

bool ksu_has_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return false;
    return READ_ONCE(syscall_hooks[nr]) != NULL;
}

#ifdef CONFIG_COMPAT
int ksu_register_compat_syscall_hook(int nr, ksu_syscall_hook_fn fn)
{
    if (nr < 0 || nr >= __NR_compat_syscalls)
        return -EINVAL;
    if (READ_ONCE(compat_syscall_hooks[nr])) {
        pr_warn("compat syscall hook for nr=%d already registered, skip\n", nr);
        return -EEXIST;
    }
    WRITE_ONCE(compat_syscall_hooks[nr], fn);
    pr_info("registered compat syscall hook for nr=%d\n", nr);
    return 0;
}

void ksu_unregister_compat_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_compat_syscalls)
        return;
    WRITE_ONCE(compat_syscall_hooks[nr], NULL);
    pr_info("unregistered compat syscall hook for nr=%d\n", nr);
}

bool ksu_has_compat_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_compat_syscalls)
        return false;
    return READ_ONCE(compat_syscall_hooks[nr]) != NULL;
}
#endif

void __init ksu_syscall_hook_init(void)
{
    int ni_slot;

    memset(syscall_hooks, 0, sizeof(syscall_hooks));
#ifdef CONFIG_COMPAT
    memset(compat_syscall_hooks, 0, sizeof(compat_syscall_hooks));
    compat_dispatcher_orig = NULL;
    compat_dispatcher_patched = false;
#endif

    ksu_syscall_table = (syscall_fn_t *)ksu_resolve_symbol_for_functable_hook("sys_call_table");
    pr_info("sys_call_table=0x%lx\n", (unsigned long)ksu_syscall_table);

    if (ksu_syscall_table) {
        if (ksu_find_ni_syscall_slots(ksu_syscall_table, __NR_syscalls, "native", &ni_slot, 1) < 1) {
            pr_err("failed to find native ni_syscall slot for dispatcher\n");
        } else {
            ksu_dispatcher_nr = ni_slot;
            ksu_syscall_table_hook(ksu_dispatcher_nr, (syscall_fn_t)ksu_syscall_dispatcher, NULL);
            pr_info("native dispatcher installed at slot %d\n", ksu_dispatcher_nr);
        }
    } else {
        pr_err("native syscall table unavailable; native hooks disabled\n");
    }

#ifdef CONFIG_COMPAT
    ksu_compat_syscall_table =
        (syscall_fn_t *)ksu_resolve_symbol_for_functable_hook("compat_sys_call_table");
    pr_info("compat_sys_call_table=0x%lx\n", (unsigned long)ksu_compat_syscall_table);

    if (!ksu_compat_syscall_table) {
        pr_warn("compat syscall table unavailable; AArch32 sucompat disabled\n");
        return;
    }

    if (ksu_find_ni_syscall_slots(ksu_compat_syscall_table, __NR_compat_syscalls, "compat", &ni_slot, 1) < 1) {
        pr_warn("failed to find compat ni_syscall slot; AArch32 sucompat disabled\n");
        return;
    }

    compat_dispatcher_orig = READ_ONCE(ksu_compat_syscall_table[ni_slot]);
    if (patch_compat_syscall_table(ni_slot, (syscall_fn_t)ksu_compat_syscall_dispatcher)) {
        compat_dispatcher_orig = NULL;
        pr_warn("failed to install compat dispatcher; AArch32 sucompat disabled\n");
        return;
    }

    ksu_compat_dispatcher_nr = ni_slot;
    compat_dispatcher_patched = true;
    pr_info("compat dispatcher installed at slot %d\n", ksu_compat_dispatcher_nr);
#endif
}

void __exit ksu_syscall_hook_exit(void)
{
    int i;

#ifdef CONFIG_COMPAT
    if (compat_dispatcher_patched && ksu_compat_syscall_table && ksu_compat_dispatcher_nr >= 0 &&
        compat_dispatcher_orig) {
        if (patch_compat_syscall_table(ksu_compat_dispatcher_nr, compat_dispatcher_orig))
            pr_err("restore compat dispatcher slot %d failed\n", ksu_compat_dispatcher_nr);
    }
    compat_dispatcher_patched = false;
#endif

    if (!ksu_syscall_table)
        goto clear_state;

    // First, restore all patched syscall table entries while the dispatcher
    // and hook table are still intact, so in-flight syscalls see valid state.
    mutex_lock(&hooked_entries_lock);
    for (i = 0; i < hooked_count; i++) {
        int nr = hooked_entries[i].nr;
        syscall_fn_t orig = hooked_entries[i].orig;

        pr_info("restore syscall %d to 0x%lx\n", nr, (unsigned long)orig);
        if (ksu_patch_text(&ksu_syscall_table[nr], &orig, sizeof(orig), KSU_PATCH_TEXT_FLUSH_DCACHE)) {
            pr_err("restore syscall %d failed\n", nr);
        }
    }
    hooked_count = 0;
    mutex_unlock(&hooked_entries_lock);

clear_state:
    // Now that the syscall table is restored, clear internal state.
    // At this point the tracepoint is already unregistered and synchronized
    // (done by ksu_syscall_hook_manager_exit before calling us), so no new
    // dispatches will occur.
    memset(syscall_hooks, 0, sizeof(syscall_hooks));
    ksu_dispatcher_nr = -1;
#ifdef CONFIG_COMPAT
    memset(compat_syscall_hooks, 0, sizeof(compat_syscall_hooks));
    ksu_compat_dispatcher_nr = -1;
    compat_dispatcher_orig = NULL;
    ksu_compat_syscall_table = NULL;
#endif

    pr_info("all syscall hooks restored\n");
}

#endif /* __aarch64__ */
