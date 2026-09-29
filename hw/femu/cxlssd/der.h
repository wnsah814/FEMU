/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_DER_H
#define FEMU_CXL_DER_H

#include "hw/cxl/cxl_device.h"
#include "cache.h"
#include "cylon.h"
#include "uffd.h"

typedef struct FemuCxlDer {
    CXLType3Dev *dev;
    GHashTable *maps;
    bool available;
    bool warned;
    bool cylon;
    FemuCylon *fast;
    bool uffd;
    FemuUffd *uffd_state;
    /* uffd: charge one page of media time starting at @stime; returns ns */
    int64_t (*media)(void *opaque, uint64_t lpn, bool write, int64_t stime);
    void *media_opaque;
    uint64_t uffd_faults;
    uint64_t uffd_wp_faults;
    uint64_t uffd_pending_victims;
    uint64_t uffd_stop_faults;  /* faults taken after a stop request */
    /* handler time, ns: FTL calls, victim zaps, continues, and all work */
    uint64_t uffd_ns_ftl;
    uint64_t uffd_ns_zap;
    uint64_t uffd_ns_continue;
    uint64_t uffd_ns_busy;
    FemuCxlCache *cache;
    uint64_t remaps;
    uint64_t revocations;
    uint64_t fallbacks;
    uint64_t probes;
    uint64_t mapped;
} FemuCxlDer;

void femu_cxl_der_init(FemuCxlDer *der, CXLType3Dev *dev, const char *mode,
                       FemuCxlCache *cache);
bool femu_cxl_der_map(FemuCxlDer *der, uint64_t hpa, uint64_t dpa);
void femu_cxl_der_remove(FemuCxlDer *der, uint64_t lpn);
void femu_cxl_der_clear(FemuCxlDer *der);
void femu_cxl_der_fallback(FemuCxlDer *der, const char *reason);
void femu_cxl_der_destroy(FemuCxlDer *der);

#endif
