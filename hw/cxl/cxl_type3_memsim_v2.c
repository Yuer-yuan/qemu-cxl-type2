/*
 * CXL Type-3 protocol-v2 CXLMemSim adapter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/cxl/cxl_type3_memsim_v2.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/units.h"
#include "system/address-spaces.h"
#include "system/memory.h"

#define CXL_TYPE3_MEMSIM_V2_DEFAULT_PORT 9300
#define CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_CAPACITY (256 * KiB)
#define CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_WAYS 4
#define CXL_TYPE3_MEMSIM_V2_DEFAULT_TIMEOUT_MS 5000

typedef struct CxlType3DirectMap {
  IOMMUMemoryRegion *iommu;
  hwaddr iova;
  uint64_t generation;
  bool active;
} CxlType3DirectMap;

typedef struct CxlType3DirectMapState {
  QemuMutex lock;
  GHashTable *by_dpa;
  uint64_t grants;
  uint64_t read_grants;
  uint64_t write_grants;
  uint64_t read_grant_ns;
  uint64_t write_grant_ns;
  uint64_t registrations;
  uint64_t invalidations;
  uint64_t invalidation_notify_ns;
  uint64_t fence_seq;
  uint64_t next_registration_generation;
} CxlType3DirectMapState;

static CxlType3DirectMapState *
cxl_type3_memsim_v2_direct_maps(CxlType3MemsimV2 *state) {
  return state ? state->direct_map_state : NULL;
}

static bool cxl_type3_memsim_v2_register_direct_map(CxlType3MemsimV2 *state,
                                                    uint64_t dpa,
                                                    IOMMUMemoryRegion *iommu,
                                                    hwaddr iova, Error **errp) {
  CxlType3DirectMapState *maps = cxl_type3_memsim_v2_direct_maps(state);
  CxlType3DirectMap *entry;
  GPtrArray *aliases;
  uint64_t *key;
  uint64_t generation;
  guint index;

  if (!maps || !iommu) {
    error_setg(errp, "missing CXL Type-3 direct-map state");
    return false;
  }
  dpa &= ~(uint64_t)(CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1);
  iova &= ~(hwaddr)(CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE - 1);
  qemu_mutex_lock(&maps->lock);
  if (maps->next_registration_generation == UINT64_MAX) {
    qemu_mutex_unlock(&maps->lock);
    error_setg(errp, "CXL Type-3 direct-map generation space exhausted");
    return false;
  }
  generation = ++maps->next_registration_generation;
  aliases = g_hash_table_lookup(maps->by_dpa, &dpa);
  if (!aliases) {
    key = g_new(uint64_t, 1);
    *key = dpa;
    aliases = g_ptr_array_new_with_free_func(g_free);
    g_hash_table_insert(maps->by_dpa, key, aliases);
  }
  for (index = 0; index < aliases->len; index++) {
    entry = g_ptr_array_index(aliases, index);
    if (entry->iommu == iommu && entry->iova == iova) {
      entry->generation = generation;
      entry->active = true;
      maps->registrations++;
      qemu_mutex_unlock(&maps->lock);
      return true;
    }
  }
  entry = g_new(CxlType3DirectMap, 1);
  *entry = (CxlType3DirectMap){
      .iommu = iommu,
      .iova = iova,
      .generation = generation,
      .active = true,
  };
  g_ptr_array_add(aliases, entry);
  maps->registrations++;
  qemu_mutex_unlock(&maps->lock);
  return true;
}

static bool cxl_type3_memsim_v2_invalidate_direct(
    void *opaque, void *mapping, uint64_t address, unsigned size,
    CxlMemsimV2LineState old_state, CxlMemsimV2LineState new_state,
    Error **errp) {
  CxlType3MemsimV2 *state = opaque;
  CxlType3DirectMapState *maps = cxl_type3_memsim_v2_direct_maps(state);
  GArray *snapshot;
  GPtrArray *aliases;
  uint64_t page = address & ~(uint64_t)(CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1);
  guint index;

  (void)mapping;
  (void)errp;
  if (!maps || size != CXL_MEMSIM_V2_SHARED_RANGE_SIZE) {
    return false;
  }
  /* E and S are both exposed read-only, so E -> S changes no CPU right. */
  if (old_state != CXL_MEMSIM_V2_STATE_M &&
      new_state == CXL_MEMSIM_V2_STATE_S) {
    return true;
  }
  /* A shared permission range can contain multiple 4 KiB TCG mappings.  One
   * synchronous range notification revokes them as a unit. */
  snapshot = g_array_new(false, false, sizeof(CxlType3DirectMap));
  qemu_mutex_lock(&maps->lock);
  aliases = g_hash_table_lookup(maps->by_dpa, &page);
  if (aliases) {
    for (index = 0; index < aliases->len; index++) {
      CxlType3DirectMap *entry = g_ptr_array_index(aliases, index);

      if (entry->active) {
        g_array_append_val(snapshot, *entry);
      }
    }
  }
  qemu_mutex_unlock(&maps->lock);

  if (snapshot->len) {
    qemu_mutex_lock(&maps->lock);
    maps->invalidations++;
    qemu_mutex_unlock(&maps->lock);
  }
  for (index = 0; index < snapshot->len; index++) {
    CxlType3DirectMap entry = g_array_index(snapshot, CxlType3DirectMap, index);
    hwaddr range_iova =
        entry.iova & ~(hwaddr)(CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1);
    guint previous;
    bool duplicate = false;
    int64_t started_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    for (previous = 0; previous < index; previous++) {
      CxlType3DirectMap prior =
          g_array_index(snapshot, CxlType3DirectMap, previous);

      if (prior.iommu == entry.iommu &&
          (prior.iova & ~(hwaddr)(CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1)) ==
              range_iova) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      continue;
    }
    IOMMUTLBEvent event = {
        .type = IOMMU_NOTIFIER_UNMAP,
        .entry =
            {
                .target_as = &address_space_memory,
                .iova = range_iova,
                .translated_addr = 0,
                .addr_mask = CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1,
                .perm = IOMMU_NONE,
            },
    };

    memory_region_notify_iommu(entry.iommu, 0, event);
    qemu_mutex_lock(&maps->lock);
    maps->invalidation_notify_ns +=
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - started_ns;
    qemu_mutex_unlock(&maps->lock);
  }
  qemu_mutex_lock(&maps->lock);
  aliases = g_hash_table_lookup(maps->by_dpa, &page);
  if (aliases) {
    guint snapshot_index;

    for (snapshot_index = 0; snapshot_index < snapshot->len; snapshot_index++) {
      CxlType3DirectMap stale =
          g_array_index(snapshot, CxlType3DirectMap, snapshot_index);

      for (index = 0; index < aliases->len; index++) {
        CxlType3DirectMap *current = g_ptr_array_index(aliases, index);

        if (current->iommu == stale.iommu && current->iova == stale.iova &&
            current->generation == stale.generation) {
          current->active = false;
          break;
        }
      }
    }
  }
  qemu_mutex_unlock(&maps->lock);
  g_array_free(snapshot, true);
  return true;
}

static bool cxl_type3_memsim_v2_shared_access(void *opaque, void *mapping,
                                              uint64_t address, uint8_t *data,
                                              unsigned size, bool write,
                                              Error **errp) {
  AddressSpace *as = mapping;
  MemTxResult result;

  (void)opaque;
  if (!as || !data || !size) {
    error_setg(errp, "invalid CXL Type-3 shared-range mapping access");
    return false;
  }
  result =
      write
          ? address_space_write(as, address, MEMTXATTRS_UNSPECIFIED, data, size)
          : address_space_read(as, address, MEMTXATTRS_UNSPECIFIED, data, size);
  if (result != MEMTX_OK) {
    error_setg(errp,
               "CXL Type-3 shared-range mapping access failed at "
               "DPA 0x%" PRIx64,
               address);
    return false;
  }
  return true;
}

CxlType3MemsimV2Config cxl_type3_memsim_v2_default_config(void) {
  return (CxlType3MemsimV2Config){
      .server_host = "127.0.0.1",
      .server_port = CXL_TYPE3_MEMSIM_V2_DEFAULT_PORT,
      .cache_capacity = CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_CAPACITY,
      .cache_ways = CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_WAYS,
      .timeout_ms = CXL_TYPE3_MEMSIM_V2_DEFAULT_TIMEOUT_MS,
  };
}

bool cxl_type3_memsim_v2_validate(const CxlType3MemsimV2Config *config,
                                  Error **errp) {
  uint32_t cache_lines;

  if (!config) {
    error_setg(errp, "missing CXL Type-3 CXLMemSim v2 configuration");
    return false;
  }
  if (!config->enabled) {
    return true;
  }
  if (!config->server_host || !config->server_host[0] || !config->server_port) {
    error_setg(errp, "invalid CXL Type-3 CXLMemSim v2 TCP address");
    return false;
  }
  if (config->host_id >= CXL_MEMSIM_V2_MAX_ENDPOINTS) {
    error_setg(errp, "CXL Type-3 coherence-v2-host-id must be below %u",
               CXL_MEMSIM_V2_MAX_ENDPOINTS);
    return false;
  }
  if (config->cache_capacity < CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      config->cache_capacity % CXL_MEMSIM_V2_SHARED_RANGE_SIZE) {
    error_setg(errp,
               "CXL Type-3 coherence-v2 cache capacity must be a "
               "nonzero multiple of %u bytes",
               CXL_MEMSIM_V2_SHARED_RANGE_SIZE);
    return false;
  }
  cache_lines = config->cache_capacity / CXL_MEMSIM_V2_SHARED_RANGE_SIZE;
  if (!config->cache_ways || cache_lines % config->cache_ways) {
    error_setg(errp, "CXL Type-3 coherence-v2 cache ways must divide "
                     "the cache line count");
    return false;
  }
  if (!config->timeout_ms || config->timeout_ms > INT_MAX) {
    error_setg(errp, "CXL Type-3 coherence-v2 timeout is invalid");
    return false;
  }
  if (config->write_through) {
    error_setg(errp, "CXL Type-3 Legofs coherence proof requires "
                     "write-back mode");
    return false;
  }
  return true;
}

bool cxl_type3_memsim_v2_realize(CxlType3MemsimV2 *state, Error **errp) {
  Error *local_err = NULL;
  CxlType3DirectMapState *maps;

  if (!state ||
      !cxl_type3_memsim_v2_validate(state ? &state->config : NULL, errp)) {
    return false;
  }
  state->enabled = state->config.enabled;
  if (!state->enabled) {
    return true;
  }
  maps = g_new0(CxlType3DirectMapState, 1);
  qemu_mutex_init(&maps->lock);
  maps->by_dpa = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free,
                                       (GDestroyNotify)g_ptr_array_unref);
  state->direct_map_state = maps;
  state->client = cxl_memsim_v2_client_new(state->config.host_id, NULL, NULL);
  if (!state->client) {
    g_hash_table_destroy(maps->by_dpa);
    qemu_mutex_destroy(&maps->lock);
    g_free(maps);
    state->direct_map_state = NULL;
    error_setg(errp, "cannot allocate CXL Type-3 CXLMemSim v2 client");
    return false;
  }
  if (!cxl_memsim_v2_client_set_shared_access(state->client,
                                              cxl_type3_memsim_v2_shared_access,
                                              state, &local_err) ||
      !cxl_memsim_v2_client_set_shared_invalidate(
          state->client, cxl_type3_memsim_v2_invalidate_direct, state,
          &local_err) ||
      !cxl_memsim_v2_client_set_write_policy(
          state->client, CXL_MEMSIM_V2_WRITE_BACK, &local_err) ||
      !cxl_memsim_v2_client_connect(
          state->client, state->config.server_host, state->config.server_port,
          state->config.cache_capacity, state->config.cache_ways,
          state->config.timeout_ms, &local_err)) {
    cxl_memsim_v2_client_free(state->client);
    state->client = NULL;
    g_hash_table_destroy(maps->by_dpa);
    qemu_mutex_destroy(&maps->lock);
    g_free(maps);
    state->direct_map_state = NULL;
    error_propagate(errp, local_err);
    return false;
  }
  info_report("CXL Type3: MESI v2 host=%u session=%" PRIu64
              " server=%s:%u data-path=%s",
              state->config.host_id,
              cxl_memsim_v2_client_session(state->client),
              state->config.server_host, state->config.server_port,
              cxl_memsim_v2_client_has_shared_range(state->client)
                  ? "shared-dax-page-grant"
                  : "line-rpc");
  return true;
}

bool cxl_type3_memsim_v2_set_wait_service(CxlType3MemsimV2 *state,
                                          CxlMemsimV2WaitServiceHandler handler,
                                          void *opaque, Error **errp) {
  if (!state || !state->enabled || !state->client) {
    error_setg(errp, "CXL Type-3 CXLMemSim v2 client is not active");
    return false;
  }
  return cxl_memsim_v2_client_set_wait_service(state->client, handler, opaque,
                                               errp);
}

void cxl_type3_memsim_v2_unrealize(CxlType3MemsimV2 *state) {
  CxlType3DirectMapState *maps;
  CxlMemsimV2ClientStats protocol = {0};

  if (!state) {
    return;
  }
  maps = cxl_type3_memsim_v2_direct_maps(state);
  if (maps) {
    if (maps->grants) {
      cxl_memsim_v2_client_stats(state->client, &protocol);
      info_report(
          "CXL_DIRECT_FINAL_JSON "
          "{\"host\":%u,\"map_grants\":%" PRIu64 ",\"map_reads\":%" PRIu64
          ",\"map_writes\":%" PRIu64 ",\"map_read_ns\":%" PRIu64
          ",\"map_write_ns\":%" PRIu64 ",\"map_registrations\":%" PRIu64
          ",\"invalidations\":%" PRIu64 ",\"invalidation_notify_ns\":%" PRIu64
          ",\"gets\":%" PRIu64 ",\"getm\":%" PRIu64 ",\"upgrade\":%" PRIu64
          ",\"puts\":%" PRIu64 ",\"putm\":%" PRIu64 ",\"fence\":%" PRIu64
          ",\"resident\":%" PRIu64 ",\"gets_ns\":%" PRIu64
          ",\"getm_ns\":%" PRIu64 ",\"upgrade_ns\":%" PRIu64
          ",\"puts_ns\":%" PRIu64 ",\"putm_ns\":%" PRIu64
          ",\"fence_ns\":%" PRIu64 ",\"resident_ns\":%" PRIu64 "}",
          state->config.host_id, maps->grants, maps->read_grants,
          maps->write_grants, maps->read_grant_ns, maps->write_grant_ns,
          maps->registrations, maps->invalidations,
          maps->invalidation_notify_ns, protocol.gets, protocol.getm,
          protocol.upgrade, protocol.puts, protocol.putm, protocol.fence,
          protocol.resident, protocol.gets_ns, protocol.getm_ns,
          protocol.upgrade_ns, protocol.puts_ns, protocol.putm_ns,
          protocol.fence_ns, protocol.resident_ns);
    }
  }
  cxl_memsim_v2_client_free(state->client);
  state->client = NULL;
  if (maps) {
    g_hash_table_destroy(maps->by_dpa);
    qemu_mutex_destroy(&maps->lock);
    g_free(maps);
    state->direct_map_state = NULL;
  }
  state->enabled = false;
}

MemTxResult cxl_type3_memsim_v2_read(CxlType3MemsimV2 *state, AddressSpace *as,
                                     uint64_t dpa, uint64_t *value,
                                     unsigned size) {
  Error *local_err = NULL;
  bool success = false;

  if (state && state->enabled && state->client && as && value) {
    if (cxl_memsim_v2_client_has_shared_range(state->client)) {
      success =
          state->config.read_exclusive
              ? cxl_memsim_v2_shared_load_exclusive(
                    state->client, dpa, size, value, as,
                    state->config.timeout_ms, &local_err)
              : cxl_memsim_v2_shared_load(state->client, dpa, size, value, as,
                                          state->config.timeout_ms, &local_err);
    } else {
      success = state->config.read_exclusive
                    ? cxl_memsim_v2_load_exclusive(
                          state->client, dpa, size, value,
                          state->config.timeout_ms, &local_err)
                    : cxl_memsim_v2_load(state->client, dpa, size, value,
                                         state->config.timeout_ms, &local_err);
    }
  }
  if (!success) {
    if (local_err) {
      error_report_err(local_err);
    }
    return MEMTX_ERROR;
  }
  return MEMTX_OK;
}

MemTxResult cxl_type3_memsim_v2_write(CxlType3MemsimV2 *state, AddressSpace *as,
                                      uint64_t dpa, uint64_t value,
                                      unsigned size) {
  Error *local_err = NULL;
  bool success = false;

  if (state && state->enabled && state->client && as) {
    success =
        cxl_memsim_v2_client_has_shared_range(state->client)
            ? cxl_memsim_v2_shared_store(state->client, dpa, size, value, as,
                                         state->config.timeout_ms, &local_err)
            : cxl_memsim_v2_store(state->client, dpa, size, value,
                                  state->config.timeout_ms, &local_err);
  }
  if (!success) {
    if (local_err) {
      error_report_err(local_err);
    }
    return MEMTX_ERROR;
  }
  return MEMTX_OK;
}

MemTxResult cxl_type3_memsim_v2_cache_block(CxlType3MemsimV2 *state,
                                            uint64_t dpa, bool persist) {
  Error *local_err = NULL;
  MemTxResult result;

  if (!state || !state->enabled || !state->client) {
    return MEMTX_ERROR;
  }
  result = cxl_memsim_v2_cache_block(state->client, dpa, persist,
                                     state->config.timeout_ms, &local_err)
               ? MEMTX_OK
               : MEMTX_ERROR;
  if (result != MEMTX_OK) {
    if (local_err) {
      error_report_err(local_err);
    }
    return MEMTX_ERROR;
  }
  if (persist && state->direct_map_state) {
    CxlType3DirectMapState *maps = cxl_type3_memsim_v2_direct_maps(state);
    CxlMemsimV2ClientStats protocol;
    uint64_t fence_seq;
    uint64_t grants;
    uint64_t read_grants;
    uint64_t write_grants;
    uint64_t read_grant_ns;
    uint64_t write_grant_ns;
    uint64_t registrations;
    uint64_t invalidations;
    uint64_t invalidation_notify_ns;

    cxl_memsim_v2_client_stats(state->client, &protocol);
    qemu_mutex_lock(&maps->lock);
    fence_seq = ++maps->fence_seq;
    grants = maps->grants;
    read_grants = maps->read_grants;
    write_grants = maps->write_grants;
    read_grant_ns = maps->read_grant_ns;
    write_grant_ns = maps->write_grant_ns;
    registrations = maps->registrations;
    invalidations = maps->invalidations;
    invalidation_notify_ns = maps->invalidation_notify_ns;
    qemu_mutex_unlock(&maps->lock);
    info_report("CXL_DIRECT_BOUNDARY_JSON "
                "{\"host\":%u,\"seq\":%" PRIu64 ",\"dpa\":%" PRIu64
                ",\"map_grants\":%" PRIu64 ",\"map_reads\":%" PRIu64
                ",\"map_writes\":%" PRIu64 ",\"map_read_ns\":%" PRIu64
                ",\"map_write_ns\":%" PRIu64 ",\"map_registrations\":%" PRIu64
                ",\"invalidations\":%" PRIu64
                ",\"invalidation_notify_ns\":%" PRIu64 ",\"gets\":%" PRIu64
                ",\"getm\":%" PRIu64 ",\"upgrade\":%" PRIu64
                ",\"puts\":%" PRIu64 ",\"putm\":%" PRIu64 ",\"fence\":%" PRIu64
                ",\"resident\":%" PRIu64 ",\"gets_ns\":%" PRIu64
                ",\"getm_ns\":%" PRIu64 ",\"upgrade_ns\":%" PRIu64
                ",\"puts_ns\":%" PRIu64 ",\"putm_ns\":%" PRIu64
                ",\"fence_ns\":%" PRIu64 ",\"resident_ns\":%" PRIu64 "}",
                state->config.host_id, fence_seq, dpa, grants, read_grants,
                write_grants, read_grant_ns, write_grant_ns, registrations,
                invalidations, invalidation_notify_ns, protocol.gets,
                protocol.getm, protocol.upgrade, protocol.puts, protocol.putm,
                protocol.fence, protocol.resident, protocol.gets_ns,
                protocol.getm_ns, protocol.upgrade_ns, protocol.puts_ns,
                protocol.putm_ns, protocol.fence_ns, protocol.resident_ns);
  }
  return result;
}

bool cxl_type3_memsim_v2_direct_enabled(CxlType3MemsimV2 *state) {
  return state && state->enabled && state->client && state->direct_map_state &&
         cxl_memsim_v2_client_has_shared_range(state->client);
}

bool cxl_type3_memsim_v2_direct_grant(CxlType3MemsimV2 *state, AddressSpace *as,
                                      uint64_t dpa, bool write,
                                      IOMMUMemoryRegion *iommu, hwaddr iova,
                                      IOMMUAccessFlags *perm, Error **errp) {
  CxlMemsimV2LineState grant_state;
  int64_t started_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

  if (!as || !perm || !cxl_type3_memsim_v2_direct_enabled(state) ||
      !cxl_type3_memsim_v2_register_direct_map(state, dpa, iommu, iova, errp) ||
      !cxl_memsim_v2_shared_grant(state->client, dpa, as, write, &grant_state,
                                  state->config.timeout_ms, errp)) {
    return false;
  }
  {
    CxlType3DirectMapState *maps = cxl_type3_memsim_v2_direct_maps(state);
    bool first;

    qemu_mutex_lock(&maps->lock);
    first = maps->grants++ == 0;
    if (write) {
      maps->write_grants++;
      maps->write_grant_ns +=
          qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - started_ns;
    } else {
      maps->read_grants++;
      maps->read_grant_ns +=
          qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - started_ns;
    }
    qemu_mutex_unlock(&maps->lock);
    if (first) {
      info_report("CXL Type3: TCG direct RAM mapping active host=%u "
                  "mapping-granule=%u coherence-granule=%u",
                  state->config.host_id, CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE,
                  CXL_MEMSIM_V2_SHARED_RANGE_SIZE);
    }
  }
  /* A load must never install a writable TCG entry merely because this
   * endpoint still owns M.  Only the store fault has rearmed persistence. */
  *perm = write && grant_state == CXL_MEMSIM_V2_STATE_M ? IOMMU_RW : IOMMU_RO;
  return true;
}
