/*
 * CXL Type-3 protocol-v2 CXLMemSim adapter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/cxl/cxl_type3_memsim_v2.h"
#include "qemu/bswap.h"
#include "qemu/crc32c.h"
#include "qemu/error-report.h"
#include "qemu/units.h"

#define CXL_TYPE3_MEMSIM_V2_DEFAULT_PORT 9300
#define CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_CAPACITY (256 * KiB)
#define CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_WAYS 4
#define CXL_TYPE3_MEMSIM_V2_DEFAULT_TIMEOUT_MS 5000

#define CXL_TYPE3_GPF_STATE_MAGIC UINT32_C(0x31504647) /* "GPF1" */
#define CXL_TYPE3_GPF_STATE_VERSION 1
#define CXL_TYPE3_SHUTDOWN_CLEAN 0
#define CXL_TYPE3_SHUTDOWN_DIRTY 1

typedef struct CxlType3GpfStateRecord {
    uint32_t magic;
    uint16_t version;
    uint8_t shutdown_state;
    uint8_t reserved;
    uint32_t dirty_shutdown_count;
    uint32_t checksum;
} QEMU_PACKED CxlType3GpfStateRecord;

QEMU_BUILD_BUG_ON(sizeof(CxlType3GpfStateRecord) != 16);

static ssize_t cxl_type3_gpf_read_full(int fd, void *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t bytes = read(fd, (uint8_t *)buffer + offset,
                             length - offset);

        if (bytes > 0) {
            offset += bytes;
        } else if (!bytes) {
            break;
        } else if (errno != EINTR) {
            return -1;
        }
    }
    return offset;
}

static uint32_t cxl_type3_gpf_state_checksum(CxlType3GpfStateRecord record)
{
    record.checksum = 0;
    return crc32c(UINT32_MAX, (const uint8_t *)&record, sizeof(record));
}

static bool cxl_type3_gpf_state_store(CxlType3MemsimV2 *state,
                                      uint8_t shutdown_state,
                                      uint32_t dirty_shutdown_count,
                                      Error **errp)
{
    const char *path = state->config.gpf_state_file;
    g_autofree char *temporary = g_strdup_printf("%s.tmp.XXXXXX", path);
    g_autofree char *directory = g_path_get_dirname(path);
    CxlType3GpfStateRecord record = {
        .magic = cpu_to_le32(CXL_TYPE3_GPF_STATE_MAGIC),
        .version = cpu_to_le16(CXL_TYPE3_GPF_STATE_VERSION),
        .shutdown_state = shutdown_state,
        .dirty_shutdown_count = cpu_to_le32(dirty_shutdown_count),
    };
    int fd = -1;
    int directory_fd = -1;
    bool success = false;

    record.checksum = cpu_to_le32(cxl_type3_gpf_state_checksum(record));
    fd = g_mkstemp_full(temporary, O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        error_setg_errno(errp, errno, "cannot create GPF state file '%s'",
                         temporary);
        goto out;
    }
    if (qemu_write_full(fd, &record, sizeof(record)) != sizeof(record) ||
        qemu_fdatasync(fd) < 0) {
        error_setg_errno(errp, errno, "cannot persist GPF state file '%s'",
                         temporary);
        goto out;
    }
    if (close(fd) < 0) {
        fd = -1;
        error_setg_errno(errp, errno, "cannot close GPF state file '%s'",
                         temporary);
        goto out;
    }
    fd = -1;
    if (rename(temporary, path) < 0) {
        error_setg_errno(errp, errno, "cannot replace GPF state file '%s'",
                         path);
        goto out;
    }
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0 || fsync(directory_fd) < 0) {
        error_setg_errno(errp, errno,
                         "cannot persist GPF state directory '%s'",
                         directory);
        goto out;
    }
    state->shutdown_state = shutdown_state;
    state->dirty_shutdown_count = dirty_shutdown_count;
    success = true;
out:
    if (directory_fd >= 0) {
        close(directory_fd);
    }
    if (fd >= 0) {
        close(fd);
    }
    if (!success) {
        unlink(temporary);
    }
    return success;
}

bool cxl_type3_memsim_v2_init_shutdown_state(CxlType3MemsimV2 *state,
                                             Error **errp)
{
    CxlType3GpfStateRecord record;
    uint32_t count = 0;
    uint8_t shutdown_state = CXL_TYPE3_SHUTDOWN_CLEAN;
    uint8_t extra;
    int fd;

    if (!state) {
        error_setg(errp, "missing CXL Type-3 GPF state");
        return false;
    }
    if (!state->config.gpf) {
        state->shutdown_state_loaded = true;
        state->shutdown_state = CXL_TYPE3_SHUTDOWN_CLEAN;
        state->dirty_shutdown_count = 0;
        return true;
    }
    if (!state->config.gpf_state_file || !state->config.gpf_state_file[0]) {
        error_setg(errp, "CXL Type-3 x-gpf requires x-gpf-state-file");
        return false;
    }
    fd = open(state->config.gpf_state_file, O_RDONLY | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT) {
        if (!cxl_type3_gpf_state_store(state, shutdown_state, count, errp)) {
            return false;
        }
        state->shutdown_state_loaded = true;
        return true;
    }
    if (fd < 0) {
        error_setg_errno(errp, errno, "cannot open GPF state file '%s'",
                         state->config.gpf_state_file);
        return false;
    }
    if (cxl_type3_gpf_read_full(fd, &record, sizeof(record)) !=
            sizeof(record) ||
        cxl_type3_gpf_read_full(fd, &extra, 1) != 0) {
        error_setg(errp, "invalid length for GPF state file '%s'",
                   state->config.gpf_state_file);
        close(fd);
        return false;
    }
    close(fd);
    if (le32_to_cpu(record.magic) != CXL_TYPE3_GPF_STATE_MAGIC ||
        le16_to_cpu(record.version) != CXL_TYPE3_GPF_STATE_VERSION ||
        record.reserved || record.shutdown_state > CXL_TYPE3_SHUTDOWN_DIRTY ||
        le32_to_cpu(record.checksum) !=
            cxl_type3_gpf_state_checksum(record)) {
        error_setg(errp, "corrupt GPF state file '%s'",
                   state->config.gpf_state_file);
        return false;
    }
    shutdown_state = record.shutdown_state;
    count = le32_to_cpu(record.dirty_shutdown_count);
    if (shutdown_state == CXL_TYPE3_SHUTDOWN_DIRTY && count != UINT32_MAX) {
        count++;
    }
    if (!cxl_type3_gpf_state_store(state, shutdown_state, count, errp)) {
        return false;
    }
    state->shutdown_state_loaded = true;
    return true;
}

bool cxl_type3_memsim_v2_set_shutdown_state(CxlType3MemsimV2 *state,
                                            uint8_t value, Error **errp)
{
    if (!state || !state->shutdown_state_loaded ||
        value > CXL_TYPE3_SHUTDOWN_DIRTY) {
        error_setg(errp, "invalid CXL Type-3 shutdown state");
        return false;
    }
    if (!state->config.gpf) {
        state->shutdown_state = value;
        return true;
    }
    if (state->shutdown_state == value) {
        return true;
    }
    return cxl_type3_gpf_state_store(state, value,
                                     state->dirty_shutdown_count, errp);
}

uint8_t cxl_type3_memsim_v2_get_shutdown_state(
    const CxlType3MemsimV2 *state)
{
    return state ? state->shutdown_state : CXL_TYPE3_SHUTDOWN_DIRTY;
}

uint32_t cxl_type3_memsim_v2_dirty_shutdown_count(
    const CxlType3MemsimV2 *state)
{
    return state ? state->dirty_shutdown_count : UINT32_MAX;
}

CxlType3MemsimV2Config cxl_type3_memsim_v2_default_config(void)
{
    return (CxlType3MemsimV2Config) {
        .server_host = "127.0.0.1",
        .server_port = CXL_TYPE3_MEMSIM_V2_DEFAULT_PORT,
        .cache_capacity = CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_CAPACITY,
        .cache_ways = CXL_TYPE3_MEMSIM_V2_DEFAULT_CACHE_WAYS,
        .timeout_ms = CXL_TYPE3_MEMSIM_V2_DEFAULT_TIMEOUT_MS,
    };
}

bool cxl_type3_memsim_v2_validate(const CxlType3MemsimV2Config *config,
                                  Error **errp)
{
    uint32_t cache_lines;

    if (!config) {
        error_setg(errp, "missing CXL Type-3 CXLMemSim v2 configuration");
        return false;
    }
    if (config->gpf && !config->enabled) {
        error_setg(errp, "CXL Type-3 x-gpf requires coherence-v2");
        return false;
    }
    if (config->gpf &&
        (!config->gpf_state_file || !config->gpf_state_file[0])) {
        error_setg(errp, "CXL Type-3 x-gpf requires x-gpf-state-file");
        return false;
    }
    if (config->gpf && config->timeout_ms > 75000) {
        error_setg(errp, "CXL Type-3 GPF timeout including retry exceeds "
                   "the 150 second DVSEC duration range");
        return false;
    }
    if (!config->enabled) {
        return true;
    }
    if (!config->server_host || !config->server_host[0] ||
        !config->server_port) {
        error_setg(errp, "invalid CXL Type-3 CXLMemSim v2 TCP address");
        return false;
    }
    if (config->host_id >= CXL_MEMSIM_V2_MAX_ENDPOINTS) {
        error_setg(errp, "CXL Type-3 coherence-v2-host-id must be below %u",
                   CXL_MEMSIM_V2_MAX_ENDPOINTS);
        return false;
    }
    if (config->cache_capacity < CXL_MEMSIM_V2_LINE_SIZE ||
        config->cache_capacity % CXL_MEMSIM_V2_LINE_SIZE) {
        error_setg(errp, "CXL Type-3 coherence-v2 cache capacity must be a "
                   "nonzero multiple of %u bytes",
                   CXL_MEMSIM_V2_LINE_SIZE);
        return false;
    }
    cache_lines = config->cache_capacity / CXL_MEMSIM_V2_LINE_SIZE;
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

bool cxl_type3_memsim_v2_realize(CxlType3MemsimV2 *state, Error **errp)
{
    Error *local_err = NULL;

    if (!state || !cxl_type3_memsim_v2_validate(state ? &state->config : NULL,
                                                 errp)) {
        return false;
    }
    state->enabled = state->config.enabled;
    if (!cxl_type3_memsim_v2_init_shutdown_state(state, errp)) {
        return false;
    }
    if (!state->enabled) {
        return true;
    }
    state->client = cxl_memsim_v2_client_new(state->config.host_id, NULL,
                                             NULL);
    if (!state->client) {
        error_setg(errp, "cannot allocate CXL Type-3 CXLMemSim v2 client");
        return false;
    }
    if ((state->config.gpf &&
         !cxl_memsim_v2_client_enable_gpf(state->client, &local_err)) ||
        !cxl_memsim_v2_client_set_write_policy(
            state->client, CXL_MEMSIM_V2_WRITE_BACK, &local_err) ||
        !cxl_memsim_v2_client_connect(
            state->client, state->config.server_host, state->config.server_port,
            state->config.cache_capacity, state->config.cache_ways,
            state->config.timeout_ms, &local_err)) {
        cxl_memsim_v2_client_free(state->client);
        state->client = NULL;
        error_propagate(errp, local_err);
        return false;
    }
    info_report("CXL Type3: MESI v2 host=%u session=%" PRIu64 " server=%s:%u",
                state->config.host_id,
                cxl_memsim_v2_client_session(state->client),
                state->config.server_host, state->config.server_port);
    return true;
}

void cxl_type3_memsim_v2_unrealize(CxlType3MemsimV2 *state)
{
    if (!state) {
        return;
    }
    cxl_memsim_v2_client_free(state->client);
    state->client = NULL;
    state->enabled = false;
}

MemTxResult cxl_type3_memsim_v2_read(CxlType3MemsimV2 *state,
                                     uint64_t dpa, uint64_t *value,
                                     unsigned size)
{
    Error *local_err = NULL;

    if (!state || !state->enabled || !state->client || !value ||
        !(state->config.read_exclusive ?
          cxl_memsim_v2_load_exclusive(state->client, dpa, size, value,
                                       state->config.timeout_ms, &local_err) :
          cxl_memsim_v2_load(state->client, dpa, size, value,
                             state->config.timeout_ms, &local_err))) {
        if (local_err) {
            error_report_err(local_err);
        }
        return MEMTX_ERROR;
    }
    return MEMTX_OK;
}

MemTxResult cxl_type3_memsim_v2_write(CxlType3MemsimV2 *state,
                                      uint64_t dpa, uint64_t value,
                                      unsigned size)
{
    Error *local_err = NULL;

    if (!state || !state->enabled || !state->client ||
        !cxl_memsim_v2_store(state->client, dpa, size, value,
                             state->config.timeout_ms, &local_err)) {
        if (local_err) {
            error_report_err(local_err);
        }
        return MEMTX_ERROR;
    }
    return MEMTX_OK;
}

MemTxResult cxl_type3_memsim_v2_cache_block(CxlType3MemsimV2 *state,
                                            uint64_t dpa)
{
    Error *local_err = NULL;

    if (!state || !state->enabled || !state->client ||
        !cxl_memsim_v2_cache_block(state->client, dpa,
                                   state->config.timeout_ms, &local_err)) {
        if (local_err) {
            error_report_err(local_err);
        }
        return MEMTX_ERROR;
    }
    return MEMTX_OK;
}

MemTxResult cxl_type3_memsim_v2_persist(CxlType3MemsimV2 *state)
{
    Error *local_err = NULL;

    if (!state || !state->enabled || !state->client ||
        !cxl_memsim_v2_fence(state->client, state->config.timeout_ms,
                              &local_err)) {
        if (local_err) {
            error_report_err(local_err);
        }
        return MEMTX_ERROR;
    }
    return MEMTX_OK;
}

bool cxl_type3_memsim_v2_gpf(CxlType3MemsimV2 *state, unsigned phase,
                             Error **errp)
{
    Error *local_err = NULL;
    bool success;

    if (!state || !state->enabled || !state->client || !state->config.gpf) {
        error_setg(errp, "CXL Type-3 GPF functional model is not enabled");
        return false;
    }
    success = cxl_memsim_v2_gpf(state->client, phase,
                                state->config.timeout_ms, &local_err);
    if (!success) {
        Error *state_err = NULL;

        if (!cxl_type3_memsim_v2_set_shutdown_state(
                state, CXL_TYPE3_SHUTDOWN_DIRTY, &state_err)) {
            error_report_err(state_err);
        }
        error_propagate(errp, local_err);
        return false;
    }
    if (phase == 2 && !cxl_type3_memsim_v2_set_shutdown_state(
            state, CXL_TYPE3_SHUTDOWN_CLEAN, &local_err)) {
        error_propagate(errp, local_err);
        return false;
    }
    return true;
}

uint16_t cxl_type3_memsim_v2_gpf_duration(const CxlType3MemsimV2Config *config)
{
    /* Round up the Phase 2 response deadline, including one transport retry. */
    uint64_t duration_us = 2ULL * config->timeout_ms * 1000;
    unsigned scale = 0;

    while (duration_us > 15 && scale < 7) {
        duration_us = DIV_ROUND_UP(duration_us, 10);
        scale++;
    }
    return (scale << 8) | duration_us;
}
