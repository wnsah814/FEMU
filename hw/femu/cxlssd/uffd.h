/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_UFFD_H
#define FEMU_CXL_UFFD_H

#include "hw/cxl/cxl_host.h"
#include "system/hostmem.h"
#include "cache.h"

/*
 * One instruction may need several pages mapped at once: a string copy
 * between CXL buffers, an access across a page boundary, code or page tables
 * on the device. Filling the last must not evict the others, as LIFO does
 * (its victim is the newest entry) and a small set does when they share it;
 * the instruction would fault on them in turn forever. Four ways cover code,
 * source, destination and a page-table page: a rule of thumb, not a bound.
 */
#define FEMU_UFFD_MIN_WAYS 4

typedef struct FemuUffd FemuUffd;
typedef struct FemuCxlDer FemuCxlDer;

bool femu_uffd_check(HostMemoryBackend *backend, uint32_t pages,
                     uint32_t ways, FemuCxlPolicy policy, bool cca,
                     Error **errp);
FemuUffd *femu_uffd_prepare(FemuCxlDer *der, HostMemoryBackend *backend,
                            const char **reason);
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw, Object *owner);
bool femu_uffd_installed(FemuCxlDer *der);
bool femu_uffd_map_page(FemuCxlDer *der, uint64_t lpn);
void femu_uffd_zap(FemuCxlDer *der, uint64_t lpn);
bool femu_uffd_busy(FemuCxlDer *der, uint64_t lpn);
void femu_uffd_uninstall(FemuCxlDer *der);
void femu_uffd_destroy(FemuCxlDer *der);
#endif
