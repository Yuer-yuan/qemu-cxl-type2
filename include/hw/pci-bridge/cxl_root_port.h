/*
 * CXL Root Port GPF helpers
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CXL_ROOT_PORT_H
#define CXL_ROOT_PORT_H

#include "hw/pci/pci_device.h"
#include "qapi/error.h"

#define TYPE_CXL_ROOT_PORT "cxl-rp"

bool cxl_rp_get_gpf_timeout_ms(PCIDevice *device, unsigned phase,
                               uint32_t *timeout_ms, Error **errp);

#endif /* CXL_ROOT_PORT_H */
