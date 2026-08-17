/*
 * CXL Type-3 protocol-v2 CXLMemSim adapter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CXL_TYPE3_MEMSIM_V2_H
#define CXL_TYPE3_MEMSIM_V2_H

#include "exec/memattrs.h"
#include "hw/cxl/cxl_memsim_v2.h"
#include "qapi/error.h"
#include "qemu/typedefs.h"
#include "system/memory.h"

typedef struct CxlType3MemsimV2Config {
  bool enabled;
  const char *server_host;
  uint16_t server_port;
  uint16_t host_id;
  uint32_t cache_capacity;
  uint16_t cache_ways;
  uint32_t timeout_ms;
  bool write_through;
  bool read_exclusive;
} CxlType3MemsimV2Config;

typedef struct CxlType3MemsimV2 {
  CxlType3MemsimV2Config config;
  CxlMemsimV2Client *client;
  void *direct_map_state;
  bool enabled;
} CxlType3MemsimV2;

CxlType3MemsimV2Config cxl_type3_memsim_v2_default_config(void);
bool cxl_type3_memsim_v2_validate(const CxlType3MemsimV2Config *config,
                                  Error **errp);
bool cxl_type3_memsim_v2_realize(CxlType3MemsimV2 *state, Error **errp);
bool cxl_type3_memsim_v2_set_wait_service(
    CxlType3MemsimV2 *state, CxlMemsimV2WaitServiceHandler handler,
    void *opaque, Error **errp);
void cxl_type3_memsim_v2_unrealize(CxlType3MemsimV2 *state);
MemTxResult cxl_type3_memsim_v2_read(CxlType3MemsimV2 *state, AddressSpace *as,
                                     uint64_t dpa, uint64_t *value,
                                     unsigned size);
MemTxResult cxl_type3_memsim_v2_write(CxlType3MemsimV2 *state, AddressSpace *as,
                                      uint64_t dpa, uint64_t value,
                                      unsigned size);
MemTxResult cxl_type3_memsim_v2_cache_block(CxlType3MemsimV2 *state,
                                            uint64_t dpa, bool persist);
bool cxl_type3_memsim_v2_direct_enabled(CxlType3MemsimV2 *state);
bool cxl_type3_memsim_v2_direct_grant(
    CxlType3MemsimV2 *state, AddressSpace *as, uint64_t dpa, bool write,
    IOMMUMemoryRegion *iommu, hwaddr iova, IOMMUAccessFlags *perm,
    Error **errp);

#endif /* CXL_TYPE3_MEMSIM_V2_H */
