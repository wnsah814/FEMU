/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * der=uffd: the whole window is one RAM alias of a shared memfd
 * backend, and the cache decides which pages the guest can reach by keeping
 * them in, or zapping them out of, the backend's page tables. A zapped page
 * raises a userfaultfd minor fault when anything (the guest through KVM, or
 * QEMU) touches it; the handler thread charges the miss to the FTL and resolves
 * the fault with UFFDIO_CONTINUE once the media time has passed. A page read
 * first is mapped write-protected, so its first write raises a WP fault that
 * marks it dirty; a write miss is mapped writable and dirty at once. The
 * cache, its policy, prefetch and the counters are the MMIO path's
 * (femu_cxl_lookup(), femu_cxl_fill()), shared under the cache lock; the
 * handler never takes the BQL.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qemu/userfaultfd.h"
#include "hw/core/cpu.h"
#include "system/hostmem.h"
#include "system/kvm.h"
#include "system/system.h"
#include "qemu-adapter.h"
#include "uffd.h"

#ifdef CONFIG_LINUX
#include <linux/magic.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>

/*
 * A resolved fill pins its page until the thread that faulted on it faults on
 * another page, or at most this long, so a later fill cannot zap the page
 * before the woken thread gets to it. The pin covers only the page the thread
 * waited for; an instruction that needs several pages keeps the earlier ones
 * through a hold (see UffdThread).
 */
#define UFFD_PIN_NS 1000000

/*
 * The pages a thread faulted on lately. One instruction can need more pages
 * at once than a set has ways (code, operands and page tables, each across a
 * page boundary): filling the last evicts the first, and the instruction
 * faults on them in turn forever. A thread that loses a recent page twice
 * with no fault on a page new to it in between is going round such a set,
 * and enters a hold: its recent pages that are cached cannot be evicted, and
 * a fill that then finds no victim is mapped without a slot (transient),
 * charged as an uncached access. A thread that keeps reaching new pages is
 * only thrashing a small cache, which der=off would charge the same. The
 * hold ends when the thread goes UFFD_PIN_NS without a fault, or after
 * UFFD_RECENT faults with no loss; its transient pages are then zapped.
 */
#define UFFD_RECENT 16

typedef struct UffdThread {
    uint32_t tid;
    struct {
        uint64_t lpn;
        bool lost;
        uint64_t fresh;         /* @fresh when it was last lost */
    } recent[UFFD_RECENT];
    unsigned next;              /* the ring slot to overwrite */
    unsigned used;
    uint64_t fresh;             /* faults on pages not in the ring */
    int64_t last;               /* the thread's last fault */
    unsigned since;             /* faults since the hold began or last lost */
    bool hold;
    GQueue transients;          /* UffdTimer, mapped until the hold ends */
} UffdThread;

typedef struct UffdTimer {
    uint64_t lpn;
    int64_t due;
    uint32_t tid;               /* the thread whose fault started the fill */
    bool write;
    bool resolved;
    /*
     * Served without a cache slot, because every way of its set is pinned or
     * NAND is full: charged as an uncached access and zapped when unpinned.
     */
    bool transient;
} UffdTimer;

struct FemuUffd {
    FemuCxlDer *der;
    int fd;
    int stop;
    uint8_t *host;
    uint64_t size;
    MemoryRegion *ram;          /* the backend's region */
    MemoryRegion alias;
    MemoryRegion *container;    /* where the alias was added, once */
    uint64_t base;              /* the window's HPA */
    MemoryRegion *io;           /* the device's MMIO region in the window */
    GPtrArray *holes;           /* UffdHole, one per run of uncached pages */
    bool holes_over;            /* too many runs: the window stays unmapped */
    bool installed;
    QemuThread thread;
    GHashTable *pending;        /* lpn -> UffdTimer, pages not yet evictable */
    GQueue timers;              /* fills not yet resolved, by due time */
    GQueue pins;                /* resolved fills still pinned, by due time */
    GHashTable *pinned;         /* tid -> its resolved, pinned fill */
    GQueue deferred;            /* read fills waiting for a slot */
    GHashTable *threads;        /* tid -> UffdThread */
    unsigned holding;           /* threads in a hold */
    /* Evicted pages the handler zaps together at the end of its batch. */
    GArray *zaps;
    bool batching;
};

/* A run of uncached pages that MMIO serves, so each access is charged. */
typedef struct UffdHole {
    struct rcu_head rcu;
    MemoryRegion mr;
} UffdHole;

/* Uncached runs need a KVM slot each; leave the rest for other regions. */
#define UFFD_HOLES_MAX 64

static int64_t now_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static FemuCxlMedia *uffd_media(FemuUffd *u)
{
    return container_of(u->der, FemuCxlMedia, direct);
}

/*
 * What the device is configured with and der=uffd cannot model fails realize
 * with a mode that can; what the host lacks only falls back to MMIO (see
 * femu_uffd_prepare()), as der=cylon does on an unpatched kernel.
 */
bool femu_uffd_check(HostMemoryBackend *backend, uint32_t pages,
                     uint32_t ways, FemuCxlPolicy policy, Error **errp)
{
    int fd = memory_region_get_fd(host_memory_backend_get_memory(backend));
    struct statfs fs;

    if (fd < 0 || !backend->share || !backend->prealloc ||
        fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC) {
        error_setg(errp, "der=uffd needs a shared, preallocated "
                   "memory-backend-memfd; der=memslot takes any backend");
        return false;
    }
    /* A page the cache cannot hold would stay mapped and never be charged. */
    if (!pages) {
        error_setg(errp, "der=uffd needs a cache (cache-pages > 0); without "
                   "one, der=off charges every access");
        return false;
    }
    if (policy == FEMU_CXL_LIFO || ways < FEMU_UFFD_MIN_WAYS) {
        error_setg(errp, "der=uffd needs cache-policy other than lifo and "
                   "cache-ways >= %d; der=cylon and der=memslot take any",
                   FEMU_UFFD_MIN_WAYS);
        return false;
    }
    return true;
}

/* The host's side: userfaultfd access and kernel features. */
FemuUffd *femu_uffd_prepare(FemuCxlDer *der, HostMemoryBackend *backend,
                            const char **reason)
{
    MemoryRegion *mr = host_memory_backend_get_memory(backend);
    struct uffdio_api api = {
        .api = UFFD_API,
        .features = UFFD_FEATURE_MINOR_SHMEM | UFFD_FEATURE_WP_HUGETLBFS_SHMEM |
                    UFFD_FEATURE_THREAD_ID,
    };
    const uint64_t features = api.features;
    FemuCxlMedia *s = container_of(der, FemuCxlMedia, direct);
    uint64_t size = memory_region_size(mr);
    void *view;
    FemuUffd *u;

    u = g_new0(FemuUffd, 1);
    /*
     * Kernel-mode faults (KVM's) need access to /dev/userfaultfd, or else
     * CAP_SYS_PTRACE or vm.unprivileged_userfaultfd for the system call.
     * Without KVM (TCG, qtest) every fault is QEMU's own, in user mode.
     */
    *reason = "userfaultfd for kernel faults needs /dev/userfaultfd access "
              "or CAP_SYS_PTRACE";
    u->fd = uffd_open(O_CLOEXEC | O_NONBLOCK |
                      (kvm_enabled() ? 0 : UFFD_USER_MODE_ONLY));
    if (u->fd < 0) {
        g_free(u);
        return NULL;
    }
    *reason = "the kernel lacks shmem minor faults, shmem write-protect "
              "or fault thread ids";
    if (ioctl(u->fd, UFFDIO_API, &api) ||
        (api.features & features) != features) {
        close(u->fd);
        g_free(u);
        return NULL;
    }
    /*
     * QEMU's own accesses, MMIO to uncached pages and a linked NVMe
     * controller's transfers, use a second mapping that is never registered,
     * so they reach the data without faulting. It outlives the handler: a
     * linked controller keeps the backend after this device goes away.
     */
    *reason = "uffd cannot map the backend a second time";
    view = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                memory_region_get_fd(mr),
                qemu_ram_get_fd_offset(mr->ram_block));
    if (view == MAP_FAILED) {
        close(u->fd);
        g_free(u);
        return NULL;
    }
    der->uffd_view = view;
    der->uffd_view_size = size;
    s->backend.logical_space = view;
    u->der = der;
    u->ram = mr;
    u->host = memory_region_get_ram_ptr(mr);
    u->size = size;
    u->stop = eventfd(0, EFD_CLOEXEC);
    u->pending = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL,
                                       g_free);
    g_queue_init(&u->timers);
    g_queue_init(&u->pins);
    u->pinned = g_hash_table_new(NULL, NULL);
    g_queue_init(&u->deferred);
    u->holes = g_ptr_array_new();
    u->threads = g_hash_table_new_full(NULL, NULL, NULL, g_free);
    u->zaps = g_array_new(false, false, sizeof(uint64_t));
    return u;
}

/* Map @lpn; write-protected unless @wp is false, when writes go uncaught. */
static void uffd_continue(FemuUffd *u, uint64_t lpn, bool wp)
{
    struct uffdio_continue c = {
        .range = { (uintptr_t)u->host + lpn * 4096, 4096 },
        .mode = wp ? UFFDIO_CONTINUE_MODE_WP : 0,
    };

    int64_t t = now_ns();

    /*
     * Another thread's fault on the page may have been resolved already
     * (EEXIST). On any other error, wake the waiters so they fault again
     * rather than sleep for good.
     */
    if (ioctl(u->fd, UFFDIO_CONTINUE, &c)) {
        struct uffdio_range r = { (uintptr_t)u->host + lpn * 4096, 4096 };

        if (errno != EEXIST) {
            error_report_once("femu-cxl-uffd: UFFDIO_CONTINUE: %s",
                              strerror(errno));
        }
        ioctl(u->fd, UFFDIO_WAKE, &r);
    }
    u->der->uffd_ns_continue += now_ns() - t;
    qatomic_inc(&u->der->remaps);
}

/* Wake the page's waiters without mapping it, so they fault again. */
static void uffd_wake(FemuUffd *u, uint64_t lpn)
{
    struct uffdio_range r = { (uintptr_t)u->host + lpn * 4096, 4096 };

    ioctl(u->fd, UFFDIO_WAKE, &r);
}

static void uffd_zap(FemuUffd *u, uint64_t lpn)
{
    int64_t t = now_ns();

    madvise(u->host + lpn * 4096, 4096, MADV_DONTNEED);
    u->der->uffd_ns_zap += now_ns() - t;
    u->der->uffd_zap_calls++;
    qatomic_inc(&u->der->revocations);
}

/* The cache lock is held, by the handler or by an access mapping a page. */
bool femu_uffd_map_page(FemuCxlDer *der, uint64_t lpn)
{
    /* A direct ratio page goes unwatched, as with memslot. */
    uffd_continue(der->uffd_state, lpn,
                       !femu_cxl_ratio_selected(der->ratio, lpn));
    return true;
}

/*
 * Revoke an evicted page. Under the cache lock; no-op while unmapped. The
 * handler's own evictions wait for the end of its batch (uffd_zap_flush()).
 */
void femu_uffd_zap(FemuCxlDer *der, uint64_t lpn)
{
    FemuUffd *u = der->uffd_state;

    if (!femu_uffd_installed(der)) {
        return;
    }
    if (u->batching) {
        g_array_append_val(u->zaps, lpn);
        return;
    }
    uffd_zap(u, lpn);
}

static gint lpn_cmp(gconstpointer a, gconstpointer b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;

    return x < y ? -1 : x > y;
}

/* Zap the batch's victims, one call and one TLB flush per contiguous run. */
static void uffd_zap_flush(FemuUffd *u)
{
    guint i = 0;

    g_array_sort(u->zaps, lpn_cmp);
    while (i < u->zaps->len) {
        uint64_t first = g_array_index(u->zaps, uint64_t, i);
        uint64_t n = 1;
        int64_t t = now_ns();

        while (i + n < u->zaps->len &&
               g_array_index(u->zaps, uint64_t, i + n) == first + n) {
            n++;
        }
        madvise(u->host + first * 4096, n * 4096, MADV_DONTNEED);
        u->der->uffd_ns_zap += now_ns() - t;
        u->der->uffd_zap_calls++;
        qatomic_add(&u->der->revocations, n);
        i += n;
    }
    g_array_set_size(u->zaps, 0);
}

static void uffd_holes_clear(FemuUffd *u)
{
    while (u->holes->len) {
        UffdHole *h = g_ptr_array_steal_index_fast(u->holes, 0);

        memory_region_del_subregion(u->container, &h->mr);
        object_unparent(OBJECT(&h->mr));
        /* A reader on the previous flat view may still reach the region. */
        g_free_rcu(h, rcu);
    }
}

static uint64_t uffd_runs(const unsigned long *map, uint64_t pages)
{
    uint64_t runs = 0;
    uint64_t lpn = 0;

    while (map && (lpn = find_next_bit(map, pages, lpn)) < pages) {
        lpn = find_next_zero_bit(map, pages, lpn);
        runs++;
    }
    return runs;
}

/* Each hole splits a KVM slot; leave room for the rest of the machine. */
static bool uffd_holes_room(uint64_t runs)
{
    uint64_t slots = UFFD_HOLES_MAX;

#ifdef CONFIG_KVM
    if (kvm_enabled()) {
        unsigned free = kvm_get_free_memslots();

        slots = MIN(slots, free > 8 ? free - 8 : 0);
    }
#endif
    return runs <= slots;
}

/*
 * Whether the uncached map, with [start, end) set or cleared, leaves few
 * enough runs to carve out of the window.
 */
bool femu_uffd_holes_fit(FemuCxlDer *der, const unsigned long *map,
                         uint64_t start, uint64_t end, bool set)
{
    FemuUffd *u = der->uffd_state;
    g_autofree unsigned long *after = NULL;
    uint64_t pages;

    if (!u) {
        return true;
    }
    pages = u->size / 4096;
    after = bitmap_new(pages);
    if (map) {
        bitmap_copy(after, map, pages);
    }
    if (set) {
        bitmap_set(after, start, end - start);
    } else {
        bitmap_clear(after, start, end - start);
    }
    return uffd_holes_room(uffd_runs(after, pages));
}

/* Carve each run of the uncached map out of the alias; in a transaction. */
static void uffd_holes_add(FemuUffd *u, const unsigned long *map)
{
    uint64_t pages = u->size / 4096;
    uint64_t lpn = 0;

    while (map && (lpn = find_next_bit(map, pages, lpn)) < pages) {
        uint64_t end = find_next_zero_bit(map, pages, lpn);
        UffdHole *h = g_new0(UffdHole, 1);

        memory_region_init_alias(&h->mr, u->container->owner,
                                 "femu-cxl-uffd-hole", u->io, lpn * 4096,
                                 (end - lpn) * 4096);
        memory_region_add_subregion_overlap(u->container, lpn * 4096, &h->mr,
                                            2);
        g_ptr_array_add(u->holes, h);
        lpn = end;
    }
}

/*
 * The alias would serve an uncached page at DRAM speed, so each run of
 * uncached pages is carved out of it with an alias of the device's own MMIO
 * region, above it, and every access there is charged. Called after the
 * uncached map changed, with the BQL and the gate but not the cache lock: a
 * KVM slot change waits for vCPUs, which may wait for the handler. The
 * change also drops the window's EPT entries, which the kernel refills from
 * QEMU's mapping without a userfault. Runs beyond the slots left unmap the
 * window until they fit again.
 */
void femu_uffd_holes(FemuCxlDer *der)
{
    FemuUffd *u = der->uffd_state;
    const unsigned long *map =
        container_of(der, FemuCxlMedia, direct)->cca.uncached_map;

    if (!u || !u->container) {
        return;
    }
    memory_region_transaction_begin();
    uffd_holes_clear(u);
    u->holes_over = !uffd_holes_room(uffd_runs(map, u->size / 4096));
    if (!u->holes_over) {
        uffd_holes_add(u, map);
    }
    memory_region_transaction_commit();
    if (u->holes_over) {
        femu_uffd_uninstall(der);
    }
}

static UffdThread *uffd_thread_get(FemuUffd *u, uint32_t tid)
{
    UffdThread *th = g_hash_table_lookup(u->threads, GUINT_TO_POINTER(tid));

    if (!th) {
        th = g_new0(UffdThread, 1);
        th->tid = tid;
        g_queue_init(&th->transients);
        g_hash_table_insert(u->threads, GUINT_TO_POINTER(tid), th);
    }
    return th;
}

static int uffd_recent(UffdThread *th, uint64_t lpn)
{
    for (unsigned i = 0; i < th->used; i++) {
        if (th->recent[i].lpn == lpn) {
            return i;
        }
    }
    return -1;
}

static void uffd_hold_end(FemuUffd *u, UffdThread *th)
{
    UffdTimer *t;

    th->hold = false;
    u->holding--;
    th->used = th->next = 0;
    while ((t = g_queue_pop_head(&th->transients))) {
        uffd_zap(u, t->lpn);
        g_hash_table_remove(u->pending, &t->lpn);
    }
}

/* End the holds whose thread went quiet; with @all, every hold. */
static bool uffd_holds_release(FemuUffd *u, int64_t now, bool all)
{
    GHashTableIter it;
    gpointer value;
    bool freed = false;

    if (!u->holding) {
        return false;
    }
    g_hash_table_iter_init(&it, u->threads);
    while (g_hash_table_iter_next(&it, NULL, &value)) {
        UffdThread *th = value;

        if (th->hold && (all || th->last + UFFD_PIN_NS <= now)) {
            uffd_hold_end(u, th);
            freed = true;
        }
    }
    return freed;
}

/*
 * Note @tid's fault on @lpn, which the cache does not hold: a recent page
 * lost again with no new page faulted on since puts the thread in a hold.
 */
static void uffd_note_miss(FemuUffd *u, uint32_t tid, uint64_t lpn)
{
    UffdThread *th = uffd_thread_get(u, tid);
    int i = uffd_recent(th, lpn);

    if (i < 0) {
        th->recent[th->next].lpn = lpn;
        th->recent[th->next].lost = false;
        th->next = (th->next + 1) % UFFD_RECENT;
        th->used = MAX(th->used, th->next ? th->next : UFFD_RECENT);
        th->fresh++;
    } else if (th->recent[i].lost && th->recent[i].fresh == th->fresh) {
        if (!th->hold) {
            th->hold = true;
            u->holding++;
            u->der->uffd_holds++;
        }
        th->since = 0;
    } else {
        th->recent[i].lost = true;
        th->recent[i].fresh = th->fresh;
    }
    if (th->hold && ++th->since > UFFD_RECENT) {
        uffd_hold_end(u, th);
    }
}

/* Whether a thread in a hold still needs @lpn. */
static bool uffd_held(FemuUffd *u, uint64_t lpn)
{
    GHashTableIter it;
    gpointer value;

    if (!u->holding) {
        return false;
    }
    g_hash_table_iter_init(&it, u->threads);
    while (g_hash_table_iter_next(&it, NULL, &value)) {
        UffdThread *th = value;

        if (th->hold && uffd_recent(th, lpn) >= 0) {
            return true;
        }
    }
    return false;
}

/*
 * A page still being filled, pinned for its thread, or held for an
 * instruction that needs it is no victim.
 */
bool femu_uffd_busy(FemuCxlDer *der, uint64_t lpn)
{
    FemuUffd *u = der->uffd_state;

    if (u && u->installed &&
        (g_hash_table_contains(u->pending, &lpn) || uffd_held(u, lpn))) {
        der->uffd_pending_victims++;
        return true;
    }
    return false;
}

static gint timer_cmp(gconstpointer a, gconstpointer b, gpointer unused)
{
    const UffdTimer *x = a, *y = b;

    return x->due < y->due ? -1 : x->due > y->due;
}

static void uffd_unpin(FemuUffd *u, UffdTimer *t)
{
    gpointer tid = GUINT_TO_POINTER(t->tid);
    UffdThread *th = g_hash_table_lookup(u->threads, tid);

    if (g_hash_table_lookup(u->pinned, tid) == t) {
        g_hash_table_remove(u->pinned, tid);
    }
    g_queue_remove(&u->pins, t);
    if (t->transient && th && th->hold) {
        /* The instruction may still need it: keep it until the hold ends. */
        g_queue_push_tail(&th->transients, t);
        return;
    }
    if (t->transient) {
        uffd_zap(u, t->lpn);
    }
    g_hash_table_remove(u->pending, &t->lpn);
}

/* Unpin resolved fills past their time limit; with @all, every one. */
static bool uffd_release(FemuUffd *u, int64_t now, bool all)
{
    UffdTimer *t;
    bool freed = false;

    while ((t = g_queue_peek_head(&u->pins)) && (all || t->due <= now)) {
        uffd_unpin(u, t);
        freed = true;
    }
    return freed;
}

/*
 * Give a fill whose read is charged its cache slot, and schedule it after the
 * read and the write-backs of its victims and prefetches. A victim still being
 * filled, or pinned, cannot be evicted, and a page mapped without a slot would
 * never be zapped or charged again, so the fill waits until a slot is freed.
 */
static void uffd_place(FemuUffd *u, UffdTimer *t)
{
    FemuCxlOp op = {
        .s = uffd_media(u),
        .start = MAX(t->due, now_ns()),
        .handler = true,
    };
    int64_t start = now_ns();

    if (!t->transient && !femu_cxl_fill(&op, t->lpn, t->write, u->base)) {
        UffdThread *th = g_hash_table_lookup(u->threads,
                                             GUINT_TO_POINTER(t->tid));

        /* A held instruction would wait for its own pages forever. */
        if (op.held && !(th && th->hold)) {
            g_queue_push_tail(&u->deferred, t);
            u->der->uffd_ns_ftl += now_ns() - start;
            return;
        }
        if (op.held) {
            u->der->uffd_transient_fills++;
        }
        t->transient = true;
    }
    u->der->uffd_ns_ftl += now_ns() - start;
    uffd_media(u)->cache_entries = g_hash_table_size(u->der->cache->entries);
    t->due = op.start + op.ns;
    g_queue_insert_sorted(&u->timers, t, timer_cmp, NULL);
}

/* Deferred fills take the slots that were freed, in the order they came. */
static void uffd_retry(FemuUffd *u)
{
    guint n = u->deferred.length;

    while (n--) {
        uffd_place(u, g_queue_pop_head(&u->deferred));
    }
}

static void uffd_miss(FemuUffd *u, uint64_t lpn, uint32_t tid, bool write)
{
    FemuCxlMedia *s = uffd_media(u);
    FemuCxlOp op = { .s = s, .start = now_ns(), .handler = true };
    FemuCxlEntry *e;
    UffdTimer *t;
    bool to_media;

    u->der->uffd_faults++;
    t = g_hash_table_lookup(u->pending, &lpn);
    /*
     * A CCA command or a linked NVMe write dropped the page after its fill
     * mapped it, and it was zapped: this is a new miss.
     */
    if (t && t->resolved && !t->transient &&
        !g_hash_table_contains(s->cache.entries, &lpn)) {
        u->der->uffd_dropped_fills++;
        uffd_unpin(u, t);
        uffd_retry(u);
        t = NULL;
    }
    if (t) {
        /* The fill in flight wakes every waiter; a resolved one is mapped. */
        if (t->resolved) {
            e = g_hash_table_lookup(s->cache.entries, &lpn);
            if (e) {
                e->dirty |= write;
            }
            uffd_continue(u, lpn, !(write && e));
        }
        return;
    }
    /*
     * A direct ratio page is mapped outside the cache at no media cost. A
     * ratio change uninstalls the handler, so the ratio is fixed here.
     */
    if (femu_cxl_ratio_selected(u->der->ratio, lpn)) {
        femu_uffd_map_page(u->der, lpn);
        return;
    }
    /* A linked NVMe namespace counts the page written (DULBE, LBA status). */
    if (write) {
        femu_cxl_nvme_mark(s, lpn * 4096, 4096);
    }
    /*
     * Hits are not seen: a resident page faults only when the window was
     * mapped after it was cached, or when the fault raced its fill.
     */
    e = femu_cxl_lookup(s, lpn, write, &to_media);
    if (e) {
        e->dirty |= write;
        uffd_continue(u, lpn, !write);
        return;
    }
    uffd_note_miss(u, tid, lpn);
    t = g_new0(UffdTimer, 1);
    t->lpn = lpn;
    t->tid = tid;
    t->write = write;
    t->transient = to_media;
    /* A failed read only loses timing; the data is in host memory. */
    femu_cxl_media(&op, lpn, write && to_media);
    u->der->uffd_ns_ftl += now_ns() - op.start;
    t->due = op.start + op.ns;
    g_hash_table_insert(u->pending, &t->lpn, t);
    if (to_media) {
        g_queue_insert_sorted(&u->timers, t, timer_cmp, NULL);
    } else {
        uffd_place(u, t);
    }
}

static void uffd_wp_fault(FemuUffd *u, uint64_t lpn)
{
    FemuCxlEntry *e = g_hash_table_lookup(u->der->cache->entries, &lpn);
    UffdTimer *t = g_hash_table_lookup(u->pending, &lpn);
    struct uffdio_writeprotect w = {
        .range = { (uintptr_t)u->host + lpn * 4096, 4096 },
        .mode = 0,
    };

    u->der->uffd_wp_faults++;
    femu_cxl_nvme_mark(uffd_media(u), lpn * 4096, 4096);
    if (e) {
        e->dirty = true;
    } else if (t && t->transient) {
        /* An uncached write goes to the media. */
        FemuCxlOp op = { .s = uffd_media(u), .handler = true };

        femu_cxl_media(&op, lpn, true);
    } else {
        /*
         * Evicted earlier in this batch and not zapped yet: zap it now, so
         * the unprotect finds no page and the write faults again as a miss.
         */
        uffd_zap_flush(u);
    }
    ioctl(u->fd, UFFDIO_WRITEPROTECT, &w);
}

/*
 * Resolve fills whose media time has passed, and pin their pages; with @all,
 * resolve every pending fill and unpin everything. A deferred fill waits for
 * a slot, usually one that an in-cache fill on the timer or pinned queue
 * holds; with @all those drain, and femu_uffd_uninstall() drops the fills
 * that wait for pages an MMIO access holds. A page dropped from the cache
 * while its fill was in flight is not mapped: its waiters fault again.
 */
static void uffd_fire(FemuUffd *u, bool all)
{
    int64_t now = now_ns();
    UffdTimer *t, *old;
    bool freed;

    do {
        freed = false;
        while ((t = g_queue_peek_head(&u->timers)) && (all || t->due <= now)) {
            g_queue_pop_head(&u->timers);
            if (!t->transient &&
                !g_hash_table_contains(u->der->cache->entries, &t->lpn)) {
                u->der->uffd_dropped_fills++;
                uffd_wake(u, t->lpn);
                g_hash_table_remove(u->pending, &t->lpn);
                continue;
            }
            /* The faulting write is the page's first: map it writable. */
            uffd_continue(u, t->lpn, !t->write);
            t->resolved = true;
            t->due = now + UFFD_PIN_NS;
            g_queue_push_tail(&u->pins, t);
            old = g_hash_table_lookup(u->pinned, GUINT_TO_POINTER(t->tid));
            if (old) {
                uffd_unpin(u, old);
                freed = true;
            }
            g_hash_table_insert(u->pinned, GUINT_TO_POINTER(t->tid), t);
        }
        freed |= uffd_holds_release(u, now, all);
        /* A fill may also wait for a page an MMIO access held. */
        if (uffd_release(u, now, all) || freed || u->deferred.length) {
            uffd_retry(u);
        }
    } while (all && !g_queue_is_empty(&u->timers));
}

/*
 * When the next fill or pin is due (a pin's end frees a slot for a deferred
 * fill, and zaps a page served without a slot), or a hold ends; INT64_MAX if
 * none.
 */
static int64_t uffd_next(FemuUffd *u)
{
    UffdTimer *t = g_queue_peek_head(&u->timers);
    UffdTimer *g = g_queue_peek_head(&u->pins);
    int64_t due = t ? t->due : INT64_MAX;
    GHashTableIter it;
    gpointer value;

    if (g) {
        due = MIN(due, g->due);
    }
    /*
     * A fill may wait for a victim that an MMIO access holds, which no
     * timer here ends: look again at least every pin's time.
     */
    if (u->deferred.length) {
        due = MIN(due, now_ns() + UFFD_PIN_NS);
    }
    if (u->holding) {
        g_hash_table_iter_init(&it, u->threads);
        while (g_hash_table_iter_next(&it, NULL, &value)) {
            UffdThread *th = value;

            if (th->hold) {
                due = MIN(due, th->last + UFFD_PIN_NS);
            }
        }
    }
    return due;
}

static void *uffd_thread(void *opaque)
{
    FemuUffd *u = opaque;
    FemuCxlMedia *s = uffd_media(u);
    struct uffd_msg m[32];

    for (;;) {
        struct pollfd p[2] = {
            { u->fd, POLLIN, 0 }, { u->stop, POLLIN, 0 },
        };
        struct timespec ts, *tsp = NULL;
        int64_t due;
        int64_t busy;
        uint64_t faults = 0;
        ssize_t n;

        femu_cxl_lock(s);
        due = uffd_next(u);
        if (due != INT64_MAX) {
            int64_t wait = MAX(0, due - now_ns());

            ts.tv_sec = wait / NANOSECONDS_PER_SECOND;
            ts.tv_nsec = wait % NANOSECONDS_PER_SECOND;
            tsp = &ts;
        }
        femu_cxl_unlock(s);
        /* On an error (EINTR) no revents are set; poll again. */
        if (ppoll(p, 2, tsp, NULL) < 0) {
            continue;
        }
        busy = now_ns();
        femu_cxl_lock(s);
        u->batching = true;
        while ((n = read(u->fd, m, sizeof(m))) > 0) {
            for (size_t i = 0; i < n / sizeof(m[0]); i++) {
                uint64_t flags = m[i].arg.pagefault.flags;
                uint32_t tid = m[i].arg.pagefault.feat.ptid;
                UffdTimer *pin;
                uint64_t lpn;

                if (m[i].event != UFFD_EVENT_PAGEFAULT) {
                    continue;
                }
                faults++;
                lpn = (m[i].arg.pagefault.address - (uintptr_t)u->host) / 4096;
                uffd_thread_get(u, tid)->last = now_ns();
                /* A thread faulting elsewhere has made its access. */
                pin = g_hash_table_lookup(u->pinned, GUINT_TO_POINTER(tid));
                if (pin && pin->lpn != lpn) {
                    uffd_unpin(u, pin);
                    uffd_retry(u);
                }
                if (flags & UFFD_PAGEFAULT_FLAG_WP) {
                    uffd_wp_fault(u, lpn);
                } else {
                    uffd_miss(u, lpn, tid, flags & UFFD_PAGEFAULT_FLAG_WRITE);
                }
            }
        }
        /* Victims go before the fills that replace them are mapped. */
        uffd_zap_flush(u);
        uffd_fire(u, false);
        uffd_zap_flush(u);
        u->batching = false;
        femu_cxl_unlock(s);
        u->der->uffd_ns_busy += now_ns() - busy;
        /* Stop only after taking the faults already queued. */
        if (p[1].revents) {
            u->der->uffd_stop_faults += faults;
            break;
        }
    }
    return NULL;
}

bool femu_uffd_installed(FemuCxlDer *der)
{
    return der->uffd_state && der->uffd_state->installed;
}

/*
 * UFFDIO_CONTINUE_MODE_WP (Linux 6.4) is not a feature bit: try it on page 0,
 * which the backend preallocated, and zap the page again.
 */
static bool uffd_continue_wp(FemuUffd *u)
{
    struct uffdio_continue c = {
        .range = { (uintptr_t)u->host, 4096 },
        .mode = UFFDIO_CONTINUE_MODE_WP,
    };
    bool ok = !ioctl(u->fd, UFFDIO_CONTINUE, &c) || errno == EEXIST;

    madvise(u->host, 4096, MADV_DONTNEED);
    return ok;
}

/* See femu_uffd_check(); the setters keep this true at run time. */
static bool uffd_cache_fits(FemuCxlCache *c)
{
    return c->nsets && c->policy != FEMU_CXL_LIFO &&
           c->ways >= FEMU_UFFD_MIN_WAYS;
}

/*
 * KVM faults a page in from a worker thread, for write, unless the guest
 * passes HLT through and has PV async page faults off (Linux's
 * kvm_can_do_async_pf()). A read miss then arrives as a write miss: the page
 * is charged a program at eviction, and the fault waits longer. The guest's
 * configuration is not the device's, so only warn.
 */
static void uffd_check_guest(void)
{
    static bool warned;
    bool asyncpf = false;
    CPUState *cs;

    if (!kvm_enabled() || warned) {
        return;
    }
    CPU_FOREACH(cs) {
        Error *err = NULL;

        asyncpf |= object_property_get_bool(OBJECT(cs), "kvm-asyncpf", &err);
        error_free(err);
    }
    if (!enable_cpu_pm || asyncpf) {
        warned = true;
        warn_report("der=uffd: the guest %s, so KVM faults pages in for "
                    "write and reads are charged as writes; use "
                    "-overcommit cpu-pm=on and -cpu ...,kvm-asyncpf=off",
                    !enable_cpu_pm ? "does not pass HLT through" :
                    "has PV async page faults on");
    }
}

/*
 * The first decoded access maps the whole window. Entries already resident
 * stay resident: their pages fault once and are continued at no media cost.
 * The caller checked that the window decodes linearly onto the backend.
 */
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw, Object *owner)
{
    FemuUffd *u = der->uffd_state;
    struct uffdio_register reg = {
        .range = { (uintptr_t)u->host, u->size },
        .mode = UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_WP,
    };
    const uint64_t ioctls = BIT_ULL(_UFFDIO_CONTINUE) |
                            BIT_ULL(_UFFDIO_WRITEPROTECT);

    if (u->installed) {
        return true;
    }
    /*
     * The access that maps the window must be the only one in the gate: with
     * overlapping misses another may still hold pages the handler would then
     * wait on. A later access maps it.
     */
    if (uffd_media(u)->accesses > 1) {
        return false;
    }
    if (!uffd_cache_fits(der->cache)) {
        der->fallbacks++;
        return false;
    }
    if (u->holes_over &&
        !uffd_holes_room(uffd_runs(uffd_media(u)->cca.uncached_map,
                                   u->size / 4096))) {
        der->fallbacks++;
        return false;
    }
    if (fw->size != u->size || (u->container && u->container != &fw->mr) ||
        !femu_cxl_window_io(fw)) {
        femu_cxl_der_fallback(der, "uffd maps one whole window onto the "
                              "backend");
        femu_uffd_destroy(der);
        return false;
    }
    if (madvise(u->host, u->size, MADV_DONTNEED) ||
        ioctl(u->fd, UFFDIO_REGISTER, &reg) ||
        (reg.ioctls & ioctls) != ioctls) {
        femu_cxl_der_fallback(der, "uffd registration failed");
        femu_uffd_destroy(der);
        return false;
    }
    if (!uffd_continue_wp(u)) {
        femu_cxl_der_fallback(der, "the kernel lacks UFFDIO_CONTINUE_MODE_WP "
                              "(Linux 6.4)");
        femu_uffd_destroy(der);
        return false;
    }
    uffd_check_guest();
    qemu_thread_create(&u->thread, "femu-cxl-uffd", uffd_thread, u,
                       QEMU_THREAD_JOINABLE);
    /*
     * The alias and its holes appear in one transaction: until it commits no
     * KVM slot covers the window, so no vCPU waits in a fault while it does,
     * even though the caller may hold the cache lock.
     */
    memory_region_transaction_begin();
    if (!u->container) {
        memory_region_init_alias(&u->alias, owner, "femu-cxl-uffd", u->ram, 0,
                                 u->size);
        memory_region_add_subregion_overlap(&fw->mr, 0, &u->alias, 1);
        u->container = &fw->mr;
        u->base = fw->base;
        u->io = femu_cxl_window_io(fw);
    } else {
        memory_region_set_enabled(&u->alias, true);
    }
    uffd_holes_clear(u);
    uffd_holes_add(u, uffd_media(u)->cca.uncached_map);
    u->holes_over = false;
    memory_region_transaction_commit();
    u->installed = true;
    der->available = true;
    qatomic_inc(&der->remaps);
    return true;
}

/*
 * Invalidation and teardown: stop the handler, resolve the faults it had in
 * flight, stop catching faults and leave accesses to the MMIO path.
 * Invalidation must not wait, but the join is short: the handler never takes
 * the BQL and holds the cache lock for one batch of faults at a time. The
 * caller must not hold the cache lock.
 */
void femu_uffd_uninstall(FemuCxlDer *der)
{
    FemuUffd *u = der->uffd_state;
    struct uffdio_range r;
    UffdTimer *t;
    uint64_t v = 1;

    if (!u || !u->installed) {
        return;
    }
    if (write(u->stop, &v, sizeof(v)) != sizeof(v)) {
        error_report("femu-cxl-uffd: cannot stop the handler");
    }
    qemu_thread_join(&u->thread);
    if (read(u->stop, &v, sizeof(v)) != sizeof(v)) {
        error_report("femu-cxl-uffd: cannot rearm the handler");
    }
    femu_cxl_lock(uffd_media(u));
    uffd_fire(u, true);
    /* Their threads are woken below and fault again on the next install. */
    while ((t = g_queue_pop_head(&u->deferred))) {
        g_hash_table_remove(u->pending, &t->lpn);
    }
    /* Every hold ended above; start the next install with no history. */
    g_hash_table_remove_all(u->threads);
    femu_cxl_unlock(uffd_media(u));
    /*
     * Unregistering wakes waiters only for missing-mode ranges, and a fault
     * that arrived after the handler's last read is still waiting. Wake the
     * range, which needs no registration, before a vCPU sleeping in a fault
     * blocks the memslot removal below.
     */
    r = (struct uffdio_range) { (uintptr_t)u->host, u->size };
    ioctl(u->fd, UFFDIO_UNREGISTER, &r);
    ioctl(u->fd, UFFDIO_WAKE, &r);
    memory_region_set_enabled(&u->alias, false);
    u->installed = false;
    der->available = false;
    qatomic_inc(&der->revocations);
}

void femu_uffd_destroy(FemuCxlDer *der)
{
    FemuUffd *u = der->uffd_state;

    if (!u) {
        return;
    }
    femu_uffd_uninstall(der);
    if (u->container) {
        memory_region_transaction_begin();
        uffd_holes_clear(u);
        memory_region_del_subregion(u->container, &u->alias);
        memory_region_transaction_commit();
        object_unparent(OBJECT(&u->alias));
    }
    g_ptr_array_free(u->holes, true);
    g_hash_table_destroy(u->threads);
    g_array_free(u->zaps, true);
    close(u->fd);
    close(u->stop);
    g_queue_clear(&u->timers);
    g_queue_clear(&u->pins);
    g_hash_table_destroy(u->pinned);
    g_queue_clear(&u->deferred);
    g_hash_table_destroy(u->pending);
    g_free(u);
    der->uffd_state = NULL;
}

/* Called when the device is freed, after any linked controller let go. */
void femu_uffd_finalize(FemuCxlDer *der)
{
    if (der->uffd_view) {
        munmap(der->uffd_view, der->uffd_view_size);
        der->uffd_view = NULL;
    }
}
#else
bool femu_uffd_check(HostMemoryBackend *backend, uint32_t pages,
                     uint32_t ways, FemuCxlPolicy policy, Error **errp)
{
    error_setg(errp, "der=uffd needs Linux");
    return false;
}

FemuUffd *femu_uffd_prepare(FemuCxlDer *der, HostMemoryBackend *backend,
                            const char **reason)
{
    *reason = "uffd needs Linux";
    return NULL;
}

bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw, Object *owner)
{
    return false;
}

bool femu_uffd_installed(FemuCxlDer *der)
{
    return false;
}

bool femu_uffd_map_page(FemuCxlDer *der, uint64_t lpn)
{
    return false;
}

void femu_uffd_zap(FemuCxlDer *der, uint64_t lpn)
{
}

bool femu_uffd_busy(FemuCxlDer *der, uint64_t lpn)
{
    return false;
}

bool femu_uffd_holes_fit(FemuCxlDer *der, const unsigned long *map,
                         uint64_t start, uint64_t end, bool set)
{
    return true;
}

void femu_uffd_holes(FemuCxlDer *der)
{
}

void femu_uffd_uninstall(FemuCxlDer *der)
{
}

void femu_uffd_destroy(FemuCxlDer *der)
{
}

void femu_uffd_finalize(FemuCxlDer *der)
{
}
#endif
