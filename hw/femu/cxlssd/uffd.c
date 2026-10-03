/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * der=uffd: the whole window is one RAM alias of a shared memfd
 * backend, and the cache decides which pages the guest can reach by keeping
 * them in, or zapping them out of, the backend's page tables. A zapped page
 * raises a userfaultfd minor fault when anything (the guest through KVM, or
 * QEMU) touches it; the handler thread charges the miss to the FTL and resolves
 * the fault with UFFDIO_CONTINUE once the media time has passed. Pages are
 * mapped write-protected, so the first write of each residency raises a WP
 * fault that marks the page dirty. The cache, its policy, prefetch and the
 * counters are the MMIO path's (femu_cxl_lookup(), femu_cxl_fill()), shared
 * under the cache lock; the handler never takes the BQL.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qemu/userfaultfd.h"
#include "system/hostmem.h"
#include "system/kvm.h"
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
 * waited for: an instruction that needs several pages keeps the earlier ones
 * only if filling the next does not evict them (see femu_uffd_prepare()).
 */
#define UFFD_PIN_NS 1000000

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
    bool installed;
    QemuThread thread;
    GHashTable *pending;        /* lpn -> UffdTimer, pages not yet evictable */
    GQueue timers;              /* fills not yet resolved, by due time */
    GQueue pins;                /* resolved fills still pinned, by due time */
    GHashTable *pinned;         /* tid -> its resolved, pinned fill */
    GQueue deferred;            /* read fills waiting for a slot */
};

static int64_t now_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

static FemuCxlMedia *uffd_media(FemuUffd *u)
{
    return container_of(u->der, FemuCxlMedia, direct);
}

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
    struct statfs fs;
    FemuUffd *u;
    int fd = memory_region_get_fd(mr);

    *reason = "uffd needs a shared, preallocated memory-backend-memfd";
    if (fd < 0 || !backend->share || !backend->prealloc ||
        fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC) {
        return NULL;
    }
    /* A page the cache cannot hold would stay mapped and never be charged. */
    *reason = "uffd needs a cache (cache-pages > 0)";
    if (!der->cache->nsets) {
        return NULL;
    }
    /*
     * One instruction may need several pages mapped at once: a string copy
     * between CXL buffers, an access across a page boundary, code or page
     * tables on the device. Filling the last must not evict the others, as
     * LIFO does (its victim is the newest entry) and a small set does when
     * they share it; the instruction would fault on them in turn forever.
     * Four ways cover code, source, destination and a page-table page: a
     * rule of thumb, not a bound.
     */
    *reason = "uffd needs cache-policy other than lifo and cache-ways >= 4";
    if (der->cache->policy == FEMU_CXL_LIFO || der->cache->ways < 4) {
        return NULL;
    }
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
    u->der = der;
    u->ram = mr;
    u->host = memory_region_get_ram_ptr(mr);
    u->size = memory_region_size(mr);
    u->stop = eventfd(0, EFD_CLOEXEC);
    u->pending = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL,
                                       g_free);
    g_queue_init(&u->timers);
    g_queue_init(&u->pins);
    u->pinned = g_hash_table_new(NULL, NULL);
    g_queue_init(&u->deferred);
    return u;
}

/* Map @lpn; write-protected unless @wp is false, when writes go uncaught. */
static void uffd_continue_mode(FemuUffd *u, uint64_t lpn, bool wp)
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

static void uffd_continue(FemuUffd *u, uint64_t lpn)
{
    uffd_continue_mode(u, lpn, true);
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
    qatomic_inc(&u->der->revocations);
}

/* The cache lock is held, by the handler or by an access mapping a page. */
bool femu_uffd_map_page(FemuCxlDer *der, uint64_t lpn)
{
    /* A direct ratio page goes unwatched, as with memslot. */
    uffd_continue_mode(der->uffd_state, lpn,
                       !femu_cxl_ratio_selected(der->ratio, lpn));
    return true;
}

/* Revoke an evicted page. Under the cache lock; no-op while unmapped. */
void femu_uffd_zap(FemuCxlDer *der, uint64_t lpn)
{
    if (femu_uffd_installed(der)) {
        uffd_zap(der->uffd_state, lpn);
    }
}

/* A page still being filled, or pinned for its thread, is no victim. */
bool femu_uffd_busy(FemuCxlDer *der, uint64_t lpn)
{
    FemuUffd *u = der->uffd_state;

    if (u && u->installed && g_hash_table_contains(u->pending, &lpn)) {
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

    if (g_hash_table_lookup(u->pinned, tid) == t) {
        g_hash_table_remove(u->pinned, tid);
    }
    g_queue_remove(&u->pins, t);
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
        if (op.held) {
            g_queue_push_tail(&u->deferred, t);
            u->der->uffd_ns_ftl += now_ns() - start;
            return;
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
    if (t) {
        /* The fill in flight wakes every waiter; a resolved one is mapped. */
        if (t->resolved) {
            uffd_continue(u, lpn);
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
    /*
     * Hits are not seen: a resident page faults only when the window was
     * mapped after it was cached, or when the fault raced its fill.
     */
    e = femu_cxl_lookup(s, lpn, write, &to_media);
    if (e) {
        uffd_continue(u, lpn);
        return;
    }
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
    if (e) {
        e->dirty = true;
    } else if (t && t->transient) {
        /* An uncached write goes to the media. */
        FemuCxlOp op = { .s = uffd_media(u), .handler = true };

        femu_cxl_media(&op, lpn, true);
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
                uffd_wake(u, t->lpn);
                g_hash_table_remove(u->pending, &t->lpn);
                continue;
            }
            uffd_continue(u, t->lpn);
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
        /* A fill may also wait for a page an MMIO access held. */
        if (uffd_release(u, now, all) || freed || u->deferred.length) {
            uffd_retry(u);
        }
    } while (all && !g_queue_is_empty(&u->timers));
}

/*
 * When the next fill or pin is due: a pin's end frees a slot for a deferred
 * fill, and zaps a page served without a slot.
 */
static UffdTimer *uffd_next(FemuUffd *u)
{
    UffdTimer *t = g_queue_peek_head(&u->timers);
    UffdTimer *g = g_queue_peek_head(&u->pins);

    return g && (!t || g->due < t->due) ? g : t;
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
        UffdTimer *t;
        int64_t busy;
        uint64_t faults = 0;
        ssize_t n;

        femu_cxl_lock(s);
        t = uffd_next(u);
        /*
         * A fill may wait for a victim that an MMIO access holds, which no
         * timer here ends: look again at least every pin's time.
         */
        if (t || u->deferred.length) {
            int64_t wait = t ? MAX(0, t->due - now_ns()) : UFFD_PIN_NS;

            if (u->deferred.length) {
                wait = MIN(wait, UFFD_PIN_NS);
            }

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
        uffd_fire(u, false);
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

/* See femu_uffd_prepare(); cache-ways can change at run time. */
static bool uffd_cache_fits(FemuCxlCache *c)
{
    return c->nsets && c->policy != FEMU_CXL_LIFO && c->ways >= 4;
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
     * fault on, and an access in flight after this one only copies (see
     * femu_cxl_access()). A later access maps it.
     */
    if (uffd_media(u)->accesses > 1) {
        return false;
    }
    if (!uffd_cache_fits(der->cache)) {
        der->fallbacks++;
        return false;
    }
    if (fw->size != u->size || (u->container && u->container != &fw->mr)) {
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
    qemu_thread_create(&u->thread, "femu-cxl-uffd", uffd_thread, u,
                       QEMU_THREAD_JOINABLE);
    if (!u->container) {
        memory_region_init_alias(&u->alias, owner, "femu-cxl-uffd", u->ram, 0,
                                 u->size);
        memory_region_add_subregion_overlap(&fw->mr, 0, &u->alias, 1);
        u->container = &fw->mr;
        u->base = fw->base;
    } else {
        memory_region_set_enabled(&u->alias, true);
    }
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
        memory_region_del_subregion(u->container, &u->alias);
        object_unparent(OBJECT(&u->alias));
    }
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
#else
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

void femu_uffd_uninstall(FemuCxlDer *der)
{
}

void femu_uffd_destroy(FemuCxlDer *der)
{
}
#endif
