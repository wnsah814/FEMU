/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_UFFD_H
#define FEMU_CXL_UFFD_H

#include "hw/cxl/cxl_host.h"
#include "system/hostmem.h"

typedef struct FemuUffd FemuUffd;
typedef struct FemuCxlDer FemuCxlDer;

FemuUffd *femu_uffd_prepare(FemuCxlDer *der, HostMemoryBackend *backend,
                            const char **reason);
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw, Object *owner);
bool femu_uffd_installed(FemuCxlDer *der);
void femu_uffd_uninstall(FemuCxlDer *der);
void femu_uffd_destroy(FemuCxlDer *der);
#endif
