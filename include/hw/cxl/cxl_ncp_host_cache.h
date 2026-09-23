/* A host-side cache model for the Type 2 NC-P integration experiment.
 *
 * The Type 2 device supplies a backing-memory callback.  The guest memory
 * access path and the simulated NIC ingress both call this object, so push
 * completion and CPU demand observe the same cache state inside QEMU.
 */
#ifndef HW_CXL_NCP_HOST_CACHE_H
#define HW_CXL_NCP_HOST_CACHE_H

#include "qapi/error.h"

typedef struct CXLNCPHostCache CXLNCPHostCache;
typedef bool (*CXLNCPBackingAccess)(void *opaque, bool write,
                                    uint64_t line_address, uint8_t data[64]);

CXLNCPHostCache *cxl_ncp_host_cache_new(uint16_t port, uint64_t capacity,
                                       uint32_t sets, uint32_t ways,
                                       CXLNCPBackingAccess backing,
                                       void *backing_opaque, Error **errp);
void cxl_ncp_host_cache_free(CXLNCPHostCache *cache);
bool cxl_ncp_host_cache_read(CXLNCPHostCache *cache, uint64_t address,
                             unsigned size, uint64_t *value, bool cxl_mem);
bool cxl_ncp_host_cache_write(CXLNCPHostCache *cache, uint64_t address,
                              unsigned size, uint64_t value, bool cxl_mem);

#endif
