/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_UFFD_H
#define FEMU_CXL_UFFD_H

#include "hw/cxl/cxl_host.h"
#include "system/hostmem.h"
#include "cache.h"

/*
 * One instruction may need several pages mapped at once: a string copy
 * between CXL buffers, an access across a page boundary, code or page tables
 * on the device. A hold keeps such an instruction going whatever the cache
 * (see UffdThread in uffd.c), but at the cost of misses der=off would not
 * charge. LIFO, whose victim is the newest entry, and sets of fewer than four
 * ways (code, source, destination and a page-table page) would put most such
 * instructions into a hold, so they are refused.
 */
#define FEMU_UFFD_MIN_WAYS 4

typedef struct FemuUffd FemuUffd;
typedef struct FemuCxlDer FemuCxlDer;

bool femu_uffd_check(HostMemoryBackend *backend, uint32_t pages,
                     uint32_t ways, FemuCxlPolicy policy, Error **errp);
FemuUffd *femu_uffd_prepare(FemuCxlDer *der, HostMemoryBackend *backend,
                            const char **reason);
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw, Object *owner);
bool femu_uffd_installed(FemuCxlDer *der);
bool femu_uffd_map_page(FemuCxlDer *der, uint64_t lpn);
void femu_uffd_zap(FemuCxlDer *der, uint64_t lpn);
bool femu_uffd_busy(FemuCxlDer *der, uint64_t lpn);
bool femu_uffd_holes_fit(FemuCxlDer *der, const unsigned long *map,
                         uint64_t start, uint64_t end, bool set);
MemoryRegion *femu_cxl_window_io(CXLFixedWindow *fw);
void femu_uffd_holes(FemuCxlDer *der);
void femu_uffd_uninstall(FemuCxlDer *der);
void femu_uffd_destroy(FemuCxlDer *der);
void femu_uffd_finalize(FemuCxlDer *der);
#endif
