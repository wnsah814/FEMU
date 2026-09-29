/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FEMU_CXL_UFFD_H
#define FEMU_CXL_UFFD_H

#include "hw/cxl/cxl_host.h"

typedef struct FemuUffd FemuUffd;
typedef struct FemuCxlDer FemuCxlDer;

FemuUffd *femu_uffd_prepare(FemuCxlDer *der, const char **reason);
bool femu_uffd_map(FemuCxlDer *der, CXLFixedWindow *fw);
bool femu_uffd_installed(FemuCxlDer *der);
void femu_uffd_uninstall(FemuCxlDer *der);
bool femu_uffd_flush(FemuCxlDer *der, uint64_t *ns);
void femu_uffd_destroy(FemuCxlDer *der);
#endif
