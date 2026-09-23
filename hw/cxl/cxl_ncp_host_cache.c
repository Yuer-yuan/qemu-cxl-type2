/* QEMU-side host cache and Type 2 CXL.cache/CXL.mem transaction model.
 *
 * The localhost ingress represents the NIC logic's D2D request to its DCOH.
 * NC-P is a device-side hint, not a CXL.cache wire opcode.  We model the
 * CXL.cache D2H Write message sequence without claiming an exact Agilex
 * opcode mapping.  CXL.mem host reads/writes are counted separately.  This is
 * a transaction-level functional model, not a link or CPU timing model.
 */
#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu/thread.h"
#include "hw/cxl/cxl_ncp_host_cache.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#define NCP_LINE_BYTES 64
#define NCP_OP_WRITE 1
#define NCP_OP_CONFIG 20
#define NCP_OP_PUSH 21
#define NCP_OP_PUSH_QUERY 22
#define NCP_OP_DDIO 23
#define NCP_OP_DDIO_QUERY 24
#define NCP_OP_TRAFFIC_QUERY 25
#define NCP_OP_NC_WRITE 26
#define NCP_OP_DEMAND_RANGE 27
#define NCP_OP_CACHE_PROTOCOL_QUERY 28
#define NCP_OP_MEM_PROTOCOL_QUERY 29

typedef struct QEMU_PACKED NCPRequest {
    uint8_t op;
    uint64_t address;
    uint64_t size;
    uint64_t timestamp;
    uint64_t value;
    uint64_t expected;
    uint8_t data[NCP_LINE_BYTES];
} NCPRequest;

typedef struct QEMU_PACKED NCPResponse {
    uint8_t status;
    uint64_t latency;
    uint64_t old_value;
    uint8_t data[NCP_LINE_BYTES];
} NCPResponse;

typedef struct NCPLine {
    uint64_t address;
    uint64_t last_use;
    uint8_t data[NCP_LINE_BYTES];
    bool valid;
    bool dirty;
} NCPLine;

typedef struct NCPDemand {
    uint64_t count;
    uint64_t hits;
} NCPDemand;

typedef enum NCPPushPhase {
    NCP_DCOH_STAGED,
    NCP_D2H_REQUEST,
    NCP_H2D_WRITE_PULL,
    NCP_D2H_DATA,
    NCP_H2D_GO_I,
    NCP_DCOH_INVALID,
} NCPPushPhase;

typedef struct NCPPushTransaction {
    uint64_t address;
    uint8_t data[NCP_LINE_BYTES];
    NCPPushPhase phase;
    bool device_line_valid;
} NCPPushTransaction;

struct CXLNCPHostCache {
    QemuMutex lock;
    QemuThread thread;
    NCPLine *lines;
    GHashTable *homes;
    GHashTable *pending;
    GHashTable *demands;
    CXLNCPBackingAccess backing;
    void *backing_opaque;
    uint64_t capacity;
    uint64_t clock;
    uint64_t pushes;
    uint64_t push_bytes;
    uint64_t ddio_writes;
    uint64_t ddio_bytes;
    uint64_t nc_writes;
    uint64_t host_reads;
    uint64_t host_read_hits;
    uint64_t first_demands;
    uint64_t first_demand_hits;
    uint64_t evictions;
    uint64_t writebacks;
    uint64_t backing_reads[2];
    uint64_t first_backing_reads[2];
    uint64_t dirty_backing_writes[2];
    uint64_t producer_backing_writes[2];
    uint64_t dcoh_staged;
    uint64_t cache_d2h_requests;
    uint64_t cache_h2d_write_pulls;
    uint64_t cache_d2h_data_bytes;
    uint64_t cache_h2d_go_i;
    uint64_t dcoh_invalidations;
    uint64_t mem_m2s_reads;
    uint64_t mem_s2m_read_data_bytes;
    uint64_t mem_s2m_read_completions;
    uint64_t mem_m2s_writes;
    uint64_t mem_m2s_write_data_bytes;
    uint64_t mem_s2m_write_completions;
    uint64_t mem_dirty_writeback_bytes;
    uint64_t dcoh_read_misses;
    uint32_t sets;
    uint32_t ways;
    int listener;
    int connection;
    bool stopping;
};

/* One shared host cache per simulated machine in the current experiment. */
static CXLNCPHostCache *system_host_cache;

/* Home 0 is host memory (DDIO), home 1 is NIC memory (NC-P). */
static int ncp_home(CXLNCPHostCache *cache, uint64_t address)
{
    void *value = g_hash_table_lookup(cache->homes, &address);
    return value ? (int)GPOINTER_TO_UINT(value) - 1 : -1;
}

static void ncp_set_home(CXLNCPHostCache *cache, uint64_t address, int home)
{
    uint64_t *key = g_new(uint64_t, 1);
    *key = address;
    g_hash_table_replace(cache->homes, key, GUINT_TO_POINTER(home + 1));
}

static NCPLine *ncp_find(CXLNCPHostCache *cache, uint64_t address)
{
    size_t base = ((address / NCP_LINE_BYTES) % cache->sets) * cache->ways;
    for (uint32_t way = 0; way < cache->ways; ++way) {
        NCPLine *line = &cache->lines[base + way];
        if (line->valid && line->address == address) {
            return line;
        }
    }
    return NULL;
}

static bool ncp_writeback(CXLNCPHostCache *cache, NCPLine *line)
{
    int home;

    if (!line->dirty) {
        return true;
    }
    home = ncp_home(cache, line->address);
    if (home == 1) {
        ++cache->mem_m2s_writes;
    }
    if (!cache->backing(cache->backing_opaque, true, line->address, line->data)) {
        return false;
    }
    if (home == 1) {
        cache->mem_m2s_write_data_bytes += NCP_LINE_BYTES;
        cache->mem_dirty_writeback_bytes += NCP_LINE_BYTES;
        ++cache->mem_s2m_write_completions;
    }
    if (home >= 0) {
        cache->dirty_backing_writes[home] += NCP_LINE_BYTES;
    }
    ++cache->writebacks;
    line->dirty = false;
    return true;
}

static bool ncp_install(CXLNCPHostCache *cache, uint64_t address,
                        const uint8_t data[NCP_LINE_BYTES], bool dirty)
{
    NCPLine *line = ncp_find(cache, address);
    if (!line) {
        size_t base = ((address / NCP_LINE_BYTES) % cache->sets) * cache->ways;
        for (uint32_t way = 0; way < cache->ways; ++way) {
            NCPLine *candidate = &cache->lines[base + way];
            if (!candidate->valid) {
                line = candidate;
                break;
            }
            if (!line || candidate->last_use < line->last_use) {
                line = candidate;
            }
        }
        if (line->valid) {
            if (!ncp_writeback(cache, line)) {
                return false;
            }
            ++cache->evictions;
        }
        line->valid = true;
        line->address = address;
        line->dirty = false;
    }
    memcpy(line->data, data, NCP_LINE_BYTES);
    line->dirty |= dirty;
    line->last_use = ++cache->clock;
    return true;
}

static bool ncp_invalidate(CXLNCPHostCache *cache, uint64_t address,
                           bool writeback)
{
    NCPLine *line = ncp_find(cache, address);
    if (!line) {
        return true;
    }
    if (writeback && !ncp_writeback(cache, line)) {
        return false;
    }
    line->valid = false;
    line->dirty = false;
    return true;
}

static bool ncp_fetch(CXLNCPHostCache *cache, uint64_t address,
                      uint8_t data[NCP_LINE_BYTES], bool demand, bool cxl_mem)
{
    NCPLine *line = ncp_find(cache, address);
    if (line) {
        memcpy(data, line->data, NCP_LINE_BYTES);
        line->last_use = ++cache->clock;
        return true;
    }
    if (cxl_mem) {
        ++cache->mem_m2s_reads;
        ++cache->dcoh_read_misses;
    }
    if (!cache->backing(cache->backing_opaque, false, address, data)) {
        return false;
    }
    if (cxl_mem) {
        cache->mem_s2m_read_data_bytes += NCP_LINE_BYTES;
        ++cache->mem_s2m_read_completions;
    }
    if (demand) {
        int home = ncp_home(cache, address);
        if (home >= 0) {
            cache->backing_reads[home] += NCP_LINE_BYTES;
            if (g_hash_table_contains(cache->pending, &address)) {
                cache->first_backing_reads[home] += NCP_LINE_BYTES;
            }
        }
    }
    return true;
}

static void ncp_mark_pending(CXLNCPHostCache *cache, uint64_t address)
{
    uint64_t *key = g_new(uint64_t, 1);
    *key = address;
    g_hash_table_replace(cache->pending, key, GUINT_TO_POINTER(1));
}

static void ncp_record_demand(CXLNCPHostCache *cache, uint64_t address,
                              bool hit)
{
    if (!g_hash_table_remove(cache->pending, &address)) {
        return;
    }
    NCPDemand *demand = g_hash_table_lookup(cache->demands, &address);
    if (!demand) {
        uint64_t *key = g_new(uint64_t, 1);
        *key = address;
        demand = g_new0(NCPDemand, 1);
        g_hash_table_insert(cache->demands, key, demand);
    }
    ++demand->count;
    ++cache->first_demands;
    if (hit) {
        ++demand->hits;
        ++cache->first_demand_hits;
    }
}

static bool ncp_guest_read_locked(CXLNCPHostCache *cache, uint64_t address,
                                  unsigned size, uint64_t *value, bool cxl_mem)
{
    uint64_t line_address = address & ~(uint64_t)(NCP_LINE_BYTES - 1);
    uint8_t data[NCP_LINE_BYTES];
    bool hit = ncp_find(cache, line_address) != NULL;
    bool ok = ncp_fetch(cache, line_address, data, true, cxl_mem);
    if (!ok || (!hit && !ncp_install(cache, line_address, data, false))) {
        return false;
    }
    *value = 0;
    memcpy(value, data + (address - line_address), size);
    ++cache->host_reads;
    if (hit) {
        ++cache->host_read_hits;
    }
    ncp_record_demand(cache, line_address, hit);
    return true;
}

static bool ncp_raw_write_locked(CXLNCPHostCache *cache, uint64_t address,
                                 unsigned size, const uint8_t *bytes,
                                 bool cxl_mem)
{
    uint64_t line_address = address & ~(uint64_t)(NCP_LINE_BYTES - 1);
    uint8_t data[NCP_LINE_BYTES];
    if (!ncp_invalidate(cache, line_address, true) ||
        !ncp_fetch(cache, line_address, data, false, false)) {
        return false;
    }
    memcpy(data + (address - line_address), bytes, size);
    if (cxl_mem) {
        ++cache->mem_m2s_writes;
    }
    if (!cache->backing(cache->backing_opaque, true, line_address, data)) {
        return false;
    }
    if (cxl_mem) {
        cache->mem_m2s_write_data_bytes += size;
        ++cache->mem_s2m_write_completions;
    }
    return true;
}

bool cxl_ncp_host_cache_read(CXLNCPHostCache *cache, uint64_t address,
                             unsigned size, uint64_t *value, bool cxl_mem)
{
    bool ok;
    if (!cache || !value || !size || size > 8 ||
        address >= cache->capacity || size > cache->capacity - address ||
        (address & 63) + size > 64) {
        return false;
    }
    qemu_mutex_lock(&cache->lock);
    ok = ncp_guest_read_locked(cache, address, size, value, cxl_mem);
    qemu_mutex_unlock(&cache->lock);
    return ok;
}

bool cxl_ncp_host_cache_write(CXLNCPHostCache *cache, uint64_t address,
                              unsigned size, uint64_t value, bool cxl_mem)
{
    bool ok;
    if (!cache || !size || size > 8 ||
        address >= cache->capacity || size > cache->capacity - address ||
        (address & 63) + size > 64) {
        return false;
    }
    qemu_mutex_lock(&cache->lock);
    ok = ncp_raw_write_locked(cache, address, size,
                              (const uint8_t *)&value, cxl_mem);
    qemu_mutex_unlock(&cache->lock);
    return ok;
}

/* Non-posted D2H Write semantic: DCOH stages a complete line, sends a D2H
 * request, receives WritePull, transfers 64 bytes, then receives GO-I only
 * after the host model has accepted the data.  Only then is the DCOH copy
 * invalidated and the NIC request completed.  Host allocation is the explicit
 * NC-P policy used by this experiment, not a CXL.cache standard guarantee.
 */
static bool ncp_dcoh_push_locked(CXLNCPHostCache *cache, uint64_t address,
                                 const uint8_t data[NCP_LINE_BYTES])
{
    NCPPushTransaction txn = {
        .address = address,
        .phase = NCP_DCOH_STAGED,
        .device_line_valid = true,
    };

    memcpy(txn.data, data, NCP_LINE_BYTES);
    ++cache->dcoh_staged;
    txn.phase = NCP_D2H_REQUEST;
    ++cache->cache_d2h_requests;
    txn.phase = NCP_H2D_WRITE_PULL;
    ++cache->cache_h2d_write_pulls;
    txn.phase = NCP_D2H_DATA;
    if (!ncp_install(cache, txn.address, txn.data, true)) {
        return false;
    }
    cache->cache_d2h_data_bytes += NCP_LINE_BYTES;
    txn.phase = NCP_H2D_GO_I;
    ++cache->cache_h2d_go_i;
    txn.device_line_valid = false;
    txn.phase = NCP_DCOH_INVALID;
    ++cache->dcoh_invalidations;
    return txn.phase == NCP_DCOH_INVALID && !txn.device_line_valid;
}

static bool ncp_producer_write_locked(CXLNCPHostCache *cache,
                                      const NCPRequest *req)
{
    uint64_t address = req->address & ~(uint64_t)(NCP_LINE_BYTES - 1);
    uint8_t data[NCP_LINE_BYTES];
    int home;
    if (req->op == NCP_OP_WRITE) {
        return ncp_raw_write_locked(cache, req->address, req->size,
                                    req->data, false);
    }
    if (!ncp_fetch(cache, address, data, false, false)) {
        return false;
    }
    memcpy(data + (req->address - address), req->data, req->size);
    if (req->op == NCP_OP_PUSH) {
        if (!ncp_dcoh_push_locked(cache, address, data)) {
            return false;
        }
        home = 1;
        ++cache->pushes;
        cache->push_bytes += req->size;
    } else if (req->op == NCP_OP_DDIO) {
        if (!ncp_invalidate(cache, address, true) ||
            !cache->backing(cache->backing_opaque, true, address, data) ||
            !ncp_install(cache, address, data, false)) {
            return false;
        }
        home = 0;
        ++cache->ddio_writes;
        cache->ddio_bytes += req->size;
        cache->producer_backing_writes[0] += NCP_LINE_BYTES;
    } else {
        /* The merged line is authoritative, so discard a dirty cache copy. */
        ncp_invalidate(cache, address, false);
        if (!cache->backing(cache->backing_opaque, true, address, data)) {
            return false;
        }
        home = 1;
        ++cache->nc_writes;
        cache->producer_backing_writes[1] += NCP_LINE_BYTES;
    }
    ncp_set_home(cache, address, home);
    ncp_mark_pending(cache, address);
    return true;
}

static uint64_t ncp_resident(CXLNCPHostCache *cache)
{
    uint64_t count = 0;
    for (uint64_t i = 0; i < (uint64_t)cache->sets * cache->ways; ++i) {
        count += cache->lines[i].valid;
    }
    return count;
}

static void ncp_response_locked(CXLNCPHostCache *cache,
                                 const NCPRequest *req, NCPResponse *resp)
{
    uint64_t values[8] = {0};
    if (req->op == NCP_OP_CONFIG) {
        if (req->value != cache->sets || req->expected != cache->ways) {
            resp->status = 1;
            return;
        }
        stq_le_p(resp->data, cache->sets);
        stq_le_p(resp->data + 8, cache->ways);
        return;
    }
    if (req->op == NCP_OP_PUSH_QUERY || req->op == NCP_OP_DDIO_QUERY) {
        values[0] = req->op == NCP_OP_PUSH_QUERY ? cache->pushes : cache->ddio_writes;
        values[1] = req->op == NCP_OP_PUSH_QUERY ? cache->push_bytes : cache->ddio_bytes;
        values[2] = cache->host_reads;
        values[3] = cache->host_read_hits;
        values[4] = cache->first_demands;
        values[5] = cache->first_demand_hits;
        values[6] = cache->evictions;
        values[7] = cache->writebacks;
        resp->old_value = ncp_resident(cache);
    } else if (req->op == NCP_OP_TRAFFIC_QUERY) {
        values[0] = cache->backing_reads[0];
        values[1] = cache->backing_reads[1];
        values[2] = cache->first_backing_reads[0];
        values[3] = cache->first_backing_reads[1];
        values[4] = cache->dirty_backing_writes[0];
        values[5] = cache->dirty_backing_writes[1];
        values[6] = cache->producer_backing_writes[0];
        values[7] = cache->producer_backing_writes[1];
    } else if (req->op == NCP_OP_CACHE_PROTOCOL_QUERY) {
        values[0] = cache->dcoh_staged;
        values[1] = cache->cache_d2h_requests;
        values[2] = cache->cache_h2d_write_pulls;
        values[3] = cache->cache_d2h_data_bytes;
        values[4] = cache->cache_h2d_go_i;
        values[5] = cache->dcoh_invalidations;
    } else if (req->op == NCP_OP_MEM_PROTOCOL_QUERY) {
        values[0] = cache->mem_m2s_reads;
        values[1] = cache->mem_s2m_read_data_bytes;
        values[2] = cache->mem_s2m_read_completions;
        values[3] = cache->mem_m2s_writes;
        values[4] = cache->mem_m2s_write_data_bytes;
        values[5] = cache->mem_s2m_write_completions;
        values[6] = cache->mem_dirty_writeback_bytes;
        values[7] = cache->dcoh_read_misses;
    } else if (req->op == NCP_OP_DEMAND_RANGE) {
        if (req->address % 64 || !req->value || req->value % 64 ||
            req->value > (1 << 20) || req->address >= cache->capacity ||
            req->value > cache->capacity - req->address) {
            resp->status = 1;
            return;
        }
        for (uint64_t address = req->address;
             address < req->address + req->value; address += 64) {
            NCPDemand *demand = g_hash_table_lookup(cache->demands, &address);
            if (demand) {
                values[0] += demand->count;
                values[1] += demand->hits;
            }
        }
    } else {
        if (req->op != NCP_OP_WRITE && req->op != NCP_OP_PUSH &&
            req->op != NCP_OP_DDIO && req->op != NCP_OP_NC_WRITE) {
            resp->status = 1;
            return;
        }
        if (!req->size || req->size > NCP_LINE_BYTES ||
            req->address >= cache->capacity ||
            req->size > cache->capacity - req->address ||
            (req->address & 63) + req->size > 64 ||
            !ncp_producer_write_locked(cache, req)) {
            resp->status = 1;
        }
        return;
    }
    for (unsigned i = 0; i < 8; ++i) {
        stq_le_p(resp->data + i * 8, values[i]);
    }
}

static bool ncp_recv_all(int fd, void *data, size_t length)
{
    uint8_t *cursor = data;
    while (length) {
        ssize_t count = recv(fd, cursor, length, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        cursor += count;
        length -= count;
    }
    return true;
}

static bool ncp_send_all(int fd, const void *data, size_t length)
{
    const uint8_t *cursor = data;
    while (length) {
        ssize_t count = send(fd, cursor, length, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        cursor += count;
        length -= count;
    }
    return true;
}

static void *ncp_ingress_thread(void *opaque)
{
    CXLNCPHostCache *cache = opaque;
    for (;;) {
        struct pollfd poll_fd = { .fd = cache->listener, .events = POLLIN };
        int ready = poll(&poll_fd, 1, 200);
        qemu_mutex_lock(&cache->lock);
        bool stop = cache->stopping;
        qemu_mutex_unlock(&cache->lock);
        if (stop) {
            break;
        }
        if (ready <= 0 || !(poll_fd.revents & POLLIN)) {
            continue;
        }
        int fd = accept(cache->listener, NULL, NULL);
        if (fd < 0) {
            continue;
        }
        qemu_mutex_lock(&cache->lock);
        cache->connection = fd;
        qemu_mutex_unlock(&cache->lock);
        for (;;) {
            NCPRequest req;
            NCPResponse resp = {0};
            if (!ncp_recv_all(fd, &req, sizeof(req))) {
                break;
            }
            qemu_mutex_lock(&cache->lock);
            ncp_response_locked(cache, &req, &resp);
            qemu_mutex_unlock(&cache->lock);
            if (!ncp_send_all(fd, &resp, sizeof(resp))) {
                break;
            }
        }
        qemu_mutex_lock(&cache->lock);
        cache->connection = -1;
        qemu_mutex_unlock(&cache->lock);
        close(fd);
    }
    return NULL;
}

CXLNCPHostCache *cxl_ncp_host_cache_new(uint16_t port, uint64_t capacity,
                                       uint32_t sets, uint32_t ways,
                                       CXLNCPBackingAccess backing,
                                       void *backing_opaque, Error **errp)
{
    CXLNCPHostCache *cache;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int listener = -1;
    int reuse = 1;
    if (!port || !capacity || !sets || !ways || sets > 65536 || ways > 64 ||
        (uint64_t)sets * ways > 1048576 || !backing) {
        error_setg(errp, "invalid QEMU NC-P host cache configuration");
        return NULL;
    }
    if (system_host_cache) {
        error_setg(errp, "only one QEMU NC-P host cache is supported per machine");
        return NULL;
    }
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 ||
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
        bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 1) < 0) {
        error_setg_errno(errp, errno, "QEMU NC-P ingress cannot listen on port %u", port);
        if (listener >= 0) {
            close(listener);
        }
        return NULL;
    }
    cache = g_new0(CXLNCPHostCache, 1);
    qemu_mutex_init(&cache->lock);
    cache->lines = g_new0(NCPLine, (size_t)sets * ways);
    cache->homes = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    cache->pending = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    cache->demands = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    cache->sets = sets;
    cache->ways = ways;
    cache->capacity = capacity;
    cache->backing = backing;
    cache->backing_opaque = backing_opaque;
    cache->listener = listener;
    cache->connection = -1;
    system_host_cache = cache;
    qemu_thread_create(&cache->thread, "cxl-ncp-ingress", ncp_ingress_thread,
                       cache, QEMU_THREAD_JOINABLE);
    return cache;
}

void cxl_ncp_host_cache_free(CXLNCPHostCache *cache)
{
    if (!cache) {
        return;
    }
    qemu_mutex_lock(&cache->lock);
    cache->stopping = true;
    if (cache->connection >= 0) {
        shutdown(cache->connection, SHUT_RDWR);
    }
    qemu_mutex_unlock(&cache->lock);
    qemu_thread_join(&cache->thread);
    close(cache->listener);
    qemu_mutex_lock(&cache->lock);
    for (uint64_t i = 0; i < (uint64_t)cache->sets * cache->ways; ++i) {
        if (cache->lines[i].valid && cache->lines[i].dirty &&
            !ncp_writeback(cache, &cache->lines[i])) {
            break;
        }
    }
    qemu_mutex_unlock(&cache->lock);
    g_hash_table_destroy(cache->homes);
    g_hash_table_destroy(cache->pending);
    g_hash_table_destroy(cache->demands);
    g_free(cache->lines);
    qemu_mutex_destroy(&cache->lock);
    system_host_cache = NULL;
    g_free(cache);
}
