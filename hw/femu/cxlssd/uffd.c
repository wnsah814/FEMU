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
#include "system/hostmem.h"
#include "der.h"
#include "uffd.h"

#ifdef CONFIG_LINUX
#include <linux/magic.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/vfs.h>

typedef struct UffdTimer {
    uint64_t lpn;
    int64_t due;
} UffdTimer;

struct FemuUffd {
    FemuCxlDer *der;
    int fd;
    int stop;
    uint8_t *host;
    uint64_t size;
    MemoryRegion alias;
    bool installed;
    QemuThread thread;
    GHashTable *pending;        /* lpn -> UffdTimer, fills not yet resolved */
    GQueue timers;              /* the same, by due time */
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
        .features = UFFD_FEATURE_MINOR_SHMEM | UFFD_FEATURE_WP_HUGETLBFS_SHMEM,
    };
    struct statfs fs;
    FemuUffd *u;
    int fd = memory_region_get_fd(mr);

    *reason = "uffd needs a shared, preallocated memory-backend-memfd";
    if (fd < 0 || !backend->share || !backend->prealloc ||
        fstatfs(fd, &fs) || fs.f_type != TMPFS_MAGIC) {
        return NULL;
    }
    u = g_new0(FemuUffd, 1);
    *reason = "userfaultfd for kernel faults needs CAP_SYS_PTRACE";
    u->fd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (u->fd < 0) {
        g_free(u);
        return NULL;
    }
    *reason = "the kernel lacks shmem minor faults or shmem write-protect";
    if (ioctl(u->fd, UFFDIO_API, &api) ||
        (api.features & (UFFD_FEATURE_MINOR_SHMEM |
                         UFFD_FEATURE_WP_HUGETLBFS_SHMEM)) !=
        (UFFD_FEATURE_MINOR_SHMEM | UFFD_FEATURE_WP_HUGETLBFS_SHMEM)) {
        close(u->fd);
        g_free(u);
        return NULL;
    }
    u->der = der;
    u->host = memory_region_get_ram_ptr(mr);
    u->size = memory_region_size(mr);
    u->stop = eventfd(0, EFD_CLOEXEC);
    u->pending = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
    g_queue_init(&u->timers);
    return u;
}

static void uffd_continue(FemuUffd *u, uint64_t lpn)
{
    struct uffdio_continue c = {
        .range = { (uintptr_t)u->host + lpn * 4096, 4096 },
        .mode = UFFDIO_CONTINUE_MODE_WP,
    };

    /* Another thread's fault on the page may have been resolved already. */
    if (ioctl(u->fd, UFFDIO_CONTINUE, &c) && errno == EEXIST) {
        struct uffdio_range r = { (uintptr_t)u->host + lpn * 4096, 4096 };

        ioctl(u->fd, UFFDIO_WAKE, &r);
    }
    u->der->remaps++;
}

static bool uffd_evict(void *opaque, FemuCxlEntry *e)
{
    FemuUffd *u = opaque;

    if (g_hash_table_contains(u->pending, &e->lpn)) {
        u->der->uffd_pending_victims++;
        return false;
    }
    /* Zap the guest's view; the data stays in the memfd's page cache. */
    madvise(u->host + e->lpn * 4096, 4096, MADV_DONTNEED);
    u->der->revocations++;
    if (e->dirty) {
        u->evict_ns += u->der->media(u->der->media_opaque, e->lpn, true,
                                     u->stime + u->evict_ns);
    }
    return true;
}

static gint timer_cmp(gconstpointer a, gconstpointer b, gpointer unused)
{
    const UffdTimer *x = a, *y = b;

    return x->due < y->due ? -1 : x->due > y->due;
}

static void uffd_miss(FemuUffd *u, uint64_t lpn)
{
    FemuCxlCache *cache = u->der->cache;
    UffdTimer *t;
    int64_t read_ns;

    u->der->uffd_faults++;
    if (g_hash_table_contains(u->pending, &lpn)) {
        return;                 /* the fill in flight wakes every waiter */
    }
    if (g_hash_table_lookup(cache->entries, &lpn)) {
        uffd_continue(u, lpn);  /* resident: a fault that raced its fill */
        return;
    }
    cache->misses++;
    u->stime = now_ns();
    read_ns = u->der->media(u->der->media_opaque, lpn, false, u->stime);
    u->evict_ns = 0;
    u->stime += read_ns;
    if (!femu_cxl_cache_insert(cache, lpn, uffd_evict, u)) {
        /* The victim is still being filled: serve this page uncached. */
        uffd_continue(u, lpn);
        return;
    }
    t = g_new(UffdTimer, 1);
    t->lpn = lpn;
    t->due = u->stime + u->evict_ns;
    g_hash_table_insert(u->pending, &t->lpn, t);
    g_queue_insert_sorted(&u->timers, t, timer_cmp, NULL);
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

static void uffd_fire(FemuUffd *u)
{
    int64_t now = now_ns();
    UffdTimer *t;

    while ((t = g_queue_peek_head(&u->timers)) && t->due <= now) {
        g_queue_pop_head(&u->timers);
        uffd_continue(u, t->lpn);
        g_hash_table_remove(u->pending, &t->lpn);
    }
}

static void *uffd_thread(void *opaque)
{
    FemuUffd *u = opaque;
    struct uffd_msg m[32];

    for (;;) {
        struct pollfd p[2] = { { u->fd, POLLIN, 0 }, { u->stop, POLLIN, 0 } };
        UffdTimer *t = g_queue_peek_head(&u->timers);
        struct timespec ts, *tsp = NULL;
        ssize_t n;

        if (t) {
            int64_t wait = MAX(0, t->due - now_ns());

            ts.tv_sec = wait / NANOSECONDS_PER_SECOND;
            ts.tv_nsec = wait % NANOSECONDS_PER_SECOND;
            tsp = &ts;
        }
        if (ppoll(p, 2, tsp, NULL) < 0 && errno != EINTR) {
            break;
        }
        if (p[1].revents) {
            break;
        }
        while ((n = read(u->fd, m, sizeof(m))) > 0) {
            for (size_t i = 0; i < n / sizeof(m[0]); i++) {
                uint64_t lpn;

                if (m[i].event != UFFD_EVENT_PAGEFAULT) {
                    continue;
                }
                lpn = (m[i].arg.pagefault.address - (uintptr_t)u->host) / 4096;
                if (m[i].arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) {
                    uffd_wp_fault(u, lpn);
                } else {
                    uffd_miss(u, lpn);
                }
            }
        }
        uffd_fire(u);
    }
    return NULL;
}

bool femu_uffd_installed(FemuCxlDer *der)
{
    return der->uffd_state && der->uffd_state->installed;
}

/* The first decoded access maps the whole window; the handler owns the cache. */
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw)
{
    FemuUffd *u = der->uffd_state;
    MemoryRegion *ram = host_memory_backend_get_memory(der->dev->hostvmem);
    struct uffdio_register reg = {
        .range = { (uintptr_t)u->host, u->size },
        .mode = UFFDIO_REGISTER_MODE_MINOR | UFFDIO_REGISTER_MODE_WP,
    };

    if (u->installed) {
        return true;
    }
    if (fw->size != u->size) {
        femu_cxl_der_fallback(der, "uffd maps the whole window onto the backend");
        der->uffd_state = NULL;
        return false;
    }
    femu_cxl_cache_clear(der->cache, NULL, NULL);
    if (madvise(u->host, u->size, MADV_DONTNEED) ||
        ioctl(u->fd, UFFDIO_REGISTER, &reg)) {
        femu_cxl_der_fallback(der, "uffd registration failed");
        der->uffd_state = NULL;
        return false;
    }
    qemu_thread_create(&u->thread, "femu-cxl-uffd", uffd_thread, u,
                       QEMU_THREAD_JOINABLE);
    memory_region_init_alias(&u->alias, OBJECT(der->dev), "femu-cxl-uffd",
                             ram, 0, u->size);
    memory_region_add_subregion_overlap(&fw->mr, 0, &u->alias, 1);
    u->installed = true;
    der->available = true;
    return true;
}

void femu_uffd_destroy(FemuCxlDer *der)
{
    FemuUffd *u = der->uffd_state;
    uint64_t one = 1;

    if (!u) {
        return;
    }
    if (u->installed) {
        if (write(u->stop, &one, sizeof(one)) != sizeof(one)) {
            error_report("femu-cxl-uffd: cannot stop the handler");
        }
        qemu_thread_join(&u->thread);
        memory_region_del_subregion(u->alias.container, &u->alias);
        object_unparent(OBJECT(&u->alias));
    }
    close(u->fd);
    close(u->stop);
    g_queue_clear_full(&u->timers, NULL);
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

void femu_uffd_destroy(FemuCxlDer *der)
{
}
#endif
