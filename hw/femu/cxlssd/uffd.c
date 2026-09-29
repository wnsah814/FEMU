/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * der=uffd, a prototype: the whole window is one RAM alias of a shared memfd
 * backend, and the cache decides which pages the guest can reach by keeping
 * them in, or zapping them out of, the backend's page tables. A zapped page
 * raises a userfaultfd minor fault when anything (the guest through KVM, or
 * QEMU) touches it; the handler thread charges the miss to the FTL and resolves
 * the fault with UFFDIO_CONTINUE once the media time has passed. Pages are
 * mapped write-protected, so the first write of each residency raises a WP
 * fault that marks the page dirty.
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/thread.h"
#include "qemu/timer.h"
#include "qemu/userfaultfd.h"
#include "hw/cxl/cxl.h"
#include "system/hostmem.h"
#include "system/kvm.h"
#include "der.h"
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
 * because the policy evicts older entries first (see femu_uffd_prepare()).
 */
#define UFFD_PIN_NS 1000000

typedef struct UffdTimer {
    uint64_t lpn;
    int64_t due;
    uint32_t tid;               /* the thread whose fault started the fill */
    bool resolved;
} UffdTimer;

struct FemuUffd {
    FemuCxlDer *der;
    int fd;
    int stop;
    int cmd;                    /* eventfd: a flush request from flush-cache */
    uint8_t *host;
    uint64_t size;
    MemoryRegion alias;
    MemoryRegion *container;    /* where the alias was added, once */
    bool installed;
    QemuThread thread;
    QemuMutex lock;             /* a flush request and its reply */
    QemuCond flushed;
    bool flush_done;
    bool flush_ok;
    int64_t flush_ns;
    GHashTable *pending;        /* lpn -> UffdTimer, pages not yet evictable */
    GQueue timers;              /* fills not yet resolved, by due time */
    GQueue pins;                /* resolved fills still pinned, by due time */
    GHashTable *pinned;         /* tid -> its resolved, pinned fill */
    GQueue deferred;            /* read fills waiting for a slot */
    int64_t evict_ns;           /* write-back time of the current miss */
    int64_t stime;
};

static int64_t now_ns(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
}

FemuUffd *femu_uffd_prepare(FemuCxlDer *der, const char **reason)
{
    HostMemoryBackend *backend = der->dev->hostvmem;
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
    *reason = "the kernel lacks shmem minor faults or shmem write-protect";
    if (ioctl(u->fd, UFFDIO_API, &api) ||
        (api.features & features) != features) {
        close(u->fd);
        g_free(u);
        return NULL;
    }
    u->der = der;
    u->host = memory_region_get_ram_ptr(mr);
    u->size = memory_region_size(mr);
    u->stop = eventfd(0, EFD_CLOEXEC);
    u->cmd = eventfd(0, EFD_CLOEXEC);
    qemu_mutex_init(&u->lock);
    qemu_cond_init(&u->flushed);
    u->pending = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    g_queue_init(&u->timers);
    g_queue_init(&u->pins);
    u->pinned = g_hash_table_new(NULL, NULL);
    g_queue_init(&u->deferred);
    return u;
}

static void uffd_continue(FemuUffd *u, uint64_t lpn)
{
    struct uffdio_continue c = {
        .range = { (uintptr_t)u->host + lpn * 4096, 4096 },
        .mode = UFFDIO_CONTINUE_MODE_WP,
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

static bool uffd_evict(void *opaque, FemuCxlEntry *e)
{
    FemuUffd *u = opaque;

    if (g_hash_table_contains(u->pending, &e->lpn)) {
        u->der->uffd_pending_victims++;
        return false;
    }
    int64_t t = now_ns();

    /* Zap the guest's view; the data stays in the memfd's page cache. */
    madvise(u->host + e->lpn * 4096, 4096, MADV_DONTNEED);
    u->der->uffd_ns_zap += now_ns() - t;
    qatomic_inc(&u->der->revocations);
    if (e->dirty) {
        t = now_ns();
        u->evict_ns += u->der->media(u->der->media_opaque, e->lpn, true,
                                     u->stime + u->evict_ns);
        u->der->uffd_ns_ftl += now_ns() - t;
    }
    return true;
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
 * read and the victim's write-back. A victim still being filled, or pinned,
 * cannot be evicted, and a page mapped without a slot would never be zapped
 * or charged again, so the fill waits until a slot is freed.
 */
static void uffd_place(FemuUffd *u, UffdTimer *t)
{
    u->stime = MAX(t->due, now_ns());
    u->evict_ns = 0;
    if (!femu_cxl_cache_insert(u->der->cache, t->lpn, uffd_evict, u)) {
        g_queue_push_tail(&u->deferred, t);
        return;
    }
    t->due = u->stime + u->evict_ns;
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

static void uffd_miss(FemuUffd *u, uint64_t lpn, uint32_t tid)
{
    FemuCxlCache *cache = u->der->cache;
    UffdTimer *t;
    int64_t stime;

    u->der->uffd_faults++;
    t = g_hash_table_lookup(u->pending, &lpn);
    if (t) {
        /* The fill in flight wakes every waiter; a resolved one is mapped. */
        if (t->resolved) {
            uffd_continue(u, lpn);
        }
        return;
    }
    if (g_hash_table_lookup(cache->entries, &lpn)) {
        uffd_continue(u, lpn);  /* resident: a fault that raced its fill */
        return;
    }
    cache->misses++;
    stime = now_ns();
    t = g_new0(UffdTimer, 1);
    t->lpn = lpn;
    t->tid = tid;
    t->due = stime + u->der->media(u->der->media_opaque, lpn, false, stime);
    u->der->uffd_ns_ftl += now_ns() - stime;
    g_hash_table_insert(u->pending, &t->lpn, t);
    uffd_place(u, t);
}

static void uffd_wp_fault(FemuUffd *u, uint64_t lpn)
{
    FemuCxlEntry *e = g_hash_table_lookup(u->der->cache->entries, &lpn);
    struct uffdio_writeprotect w = {
        .range = { (uintptr_t)u->host + lpn * 4096, 4096 },
        .mode = 0,
    };

    u->der->uffd_wp_faults++;
    if (e) {
        e->dirty = true;
    }
    ioctl(u->fd, UFFDIO_WRITEPROTECT, &w);
}

/*
 * Resolve fills whose media time has passed, and pin their pages; with @all,
 * resolve every pending fill and unpin everything. A deferred fill waits only
 * for an in-cache fill, which is on the timer or pinned queue, so with @all
 * all three drain.
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
        if (uffd_release(u, now, all) || freed) {
            uffd_retry(u);
        }
    } while (all && !g_queue_is_empty(&u->timers));
}

/* flush-cache: write back and zap every resident page, from the handler. */
static void uffd_flush(FemuUffd *u)
{
    bool ok;

    uffd_fire(u, true);
    u->stime = now_ns();
    u->evict_ns = 0;
    ok = femu_cxl_cache_clear(u->der->cache, uffd_evict, u);
    qemu_mutex_lock(&u->lock);
    u->flush_ok = ok;
    u->flush_ns = u->evict_ns;
    u->flush_done = true;
    qemu_cond_broadcast(&u->flushed);
    qemu_mutex_unlock(&u->lock);
}

static void *uffd_thread(void *opaque)
{
    FemuUffd *u = opaque;
    struct uffd_msg m[32];

    for (;;) {
        struct pollfd p[3] = {
            { u->fd, POLLIN, 0 }, { u->stop, POLLIN, 0 }, { u->cmd, POLLIN, 0 },
        };
        UffdTimer *t = g_queue_peek_head(&u->timers);
        /* A pin's time limit needs a wake-up only when a fill waits on it. */
        UffdTimer *g = u->deferred.length ? g_queue_peek_head(&u->pins)
                                          : NULL;
        struct timespec ts, *tsp = NULL;
        int64_t busy;
        uint64_t faults = 0;
        ssize_t n;

        if (g && (!t || g->due < t->due)) {
            t = g;
        }
        if (t) {
            int64_t wait = MAX(0, t->due - now_ns());

            ts.tv_sec = wait / NANOSECONDS_PER_SECOND;
            ts.tv_nsec = wait % NANOSECONDS_PER_SECOND;
            tsp = &ts;
        }
        /* On an error (EINTR) no revents are set; poll again. */
        if (ppoll(p, 3, tsp, NULL) < 0) {
            continue;
        }
        busy = now_ns();
        while ((n = read(u->fd, m, sizeof(m))) > 0) {
            for (size_t i = 0; i < n / sizeof(m[0]); i++) {
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
                if (m[i].arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
                    uffd_wp_fault(u, lpn);
                } else {
                    uffd_miss(u, lpn, tid);
                }
            }
        }
        if (p[2].revents) {
            uint64_t v;

            if (read(u->cmd, &v, sizeof(v)) == sizeof(v)) {
                uffd_flush(u);
            }
        }
        uffd_fire(u, false);
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
 * The alias maps window offset X to backend offset X, so HDM decoder 0 must
 * be the only one committed, cover the whole window and skip no DPA.
 */
static bool uffd_identity(FemuUffd *u, CXLFixedWindow *fw)
{
    uint32_t *regs = u->der->dev->cxl_cstate.crb.cache_mem_registers;
    uint64_t base, size, skip;
    unsigned i;

    for (i = 1; i < CXL_HDM_DECODER_COUNT; i++) {
        if (FIELD_EX32(ldl_le_p(regs + R_CXL_HDM_DECODER0_CTRL + i * 8),
                       CXL_HDM_DECODER0_CTRL, COMMITTED)) {
            return false;
        }
    }
    base = (uint64_t)ldl_le_p(regs + R_CXL_HDM_DECODER0_BASE_HI) << 32 |
           (ldl_le_p(regs + R_CXL_HDM_DECODER0_BASE_LO) & 0xf0000000);
    size = (uint64_t)ldl_le_p(regs + R_CXL_HDM_DECODER0_SIZE_HI) << 32 |
           (ldl_le_p(regs + R_CXL_HDM_DECODER0_SIZE_LO) & 0xf0000000);
    skip = (uint64_t)ldl_le_p(regs + R_CXL_HDM_DECODER0_DPA_SKIP_HI) << 32 |
           (ldl_le_p(regs + R_CXL_HDM_DECODER0_DPA_SKIP_LO) & 0xf0000000);
    return base == fw->base && size == fw->size && !skip;
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

/*
 * The first decoded access maps the whole window, and the handler owns the
 * cache while it is mapped. Entries already resident stay resident: their
 * pages fault once and are continued at no media cost.
 */
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw)
{
    FemuUffd *u = der->uffd_state;
    MemoryRegion *ram = host_memory_backend_get_memory(der->dev->hostvmem);
    struct uffdio_register reg = {
        .range = { (uintptr_t)u->host, u->size },
        .mode = UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_WP,
    };
    const uint64_t ioctls = BIT_ULL(_UFFDIO_CONTINUE) |
                            BIT_ULL(_UFFDIO_WRITEPROTECT);

    if (u->installed) {
        return true;
    }
    if (fw->size != u->size || (u->container && u->container != &fw->mr) ||
        !uffd_identity(u, fw)) {
        femu_cxl_der_fallback(der, "uffd maps one whole window onto the "
                              "backend, through one decoder with no skip");
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
        memory_region_init_alias(&u->alias, OBJECT(der->dev), "femu-cxl-uffd",
                                 ram, 0, u->size);
        memory_region_add_subregion_overlap(&fw->mr, 0, &u->alias, 1);
        u->container = &fw->mr;
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
 * flight, stop catching faults and hand the cache back to the MMIO path.
 */
void femu_uffd_uninstall(FemuCxlDer *der)
{
    FemuUffd *u = der->uffd_state;
    struct uffdio_range r;
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
    uffd_fire(u, true);
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

bool femu_uffd_flush(FemuCxlDer *der, uint64_t *ns)
{
    FemuUffd *u = der->uffd_state;
    uint64_t v = 1;

    qemu_mutex_lock(&u->lock);
    u->flush_done = false;
    if (write(u->cmd, &v, sizeof(v)) != sizeof(v)) {
        qemu_mutex_unlock(&u->lock);
        return false;
    }
    while (!u->flush_done) {
        qemu_cond_wait(&u->flushed, &u->lock);
    }
    *ns = u->flush_ns;
    qemu_mutex_unlock(&u->lock);
    return u->flush_ok;
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
    close(u->cmd);
    qemu_cond_destroy(&u->flushed);
    qemu_mutex_destroy(&u->lock);
    g_queue_clear(&u->timers);
    g_queue_clear(&u->pins);
    g_hash_table_destroy(u->pinned);
    g_queue_clear(&u->deferred);
    g_hash_table_destroy(u->pending);
    g_free(u);
    der->uffd_state = NULL;
}
#else
FemuUffd *femu_uffd_prepare(FemuCxlDer *der, const char **reason)
{
    *reason = "uffd needs Linux";
    return NULL;
}

bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw)
{
    return false;
}

bool femu_uffd_installed(FemuCxlDer *der)
{
    return false;
}

void femu_uffd_uninstall(FemuCxlDer *der)
{
}

bool femu_uffd_flush(FemuCxlDer *der, uint64_t *ns)
{
    return false;
}

void femu_uffd_destroy(FemuCxlDer *der)
{
}
#endif
