/*
 * CXLMemSim protocol-v2 duplex endpoint client
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/cxl/cxl_memsim_v2.h"
#include "io/channel-socket.h"
#include "qapi/qapi-types-sockets.h"
#include "qemu/atomic.h"
#include "qemu/bswap.h"
#include "qemu/thread.h"
#include "qemu/timer.h"

#define CXL_MEMSIM_V2_RESPONSE_ACK_INTERVAL 128
#define CXL_MEMSIM_V2_OPERATION_GATE_COUNT 4096
#define CXL_MEMSIM_V2_WRITEBACK_WORKERS 4
#define CXL_MEMSIM_V2_CPU_WORK_POLL_MS 1

typedef struct CxlMemsimV2Pending {
  uint64_t request_id;
  CxlMemsimV2Frame request;
  CxlMemsimV2Frame response;
  QemuCond completed;
  bool done;
  bool io_failed;
  bool retried;
} CxlMemsimV2Pending;

typedef struct CxlMemsimV2CacheLine {
  uint64_t address;
  uint64_t epoch;
  uint64_t last_used;
  uint8_t data[CXL_MEMSIM_V2_LINE_SIZE];
  uint8_t state;
  bool valid;
  bool invalidating;
  bool dirty;
  bool shared_range;
  uint64_t resident_mask;
  uint64_t writable_mask;
  void *shared_mapping;
} CxlMemsimV2CacheLine;

struct CxlMemsimV2Client {
  uint16_t endpoint;
  uint64_t session_id;
  uint64_t next_request_id;
  uint64_t consumed_response_id;
  uint64_t acknowledged_response_id;
  QIOChannelSocket *socket;
  QemuThread progress_thread;
  QemuMutex state_lock;
  QemuMutex request_lock;
  QemuMutex send_lock;
  GRWLock operation_barrier;
  QemuMutex *operation_gates;
  QemuMutex cache_lock;
  QemuMutex writeback_lock;
  QemuCond writeback_available;
  QemuCond writeback_drained;
  QemuThread writeback_threads[CXL_MEMSIM_V2_WRITEBACK_WORKERS];
  GQueue writeback_queue;
  GHashTable *writeback_pending;
  GHashTable *pending;
  GHashTable *completed_retries;
  GHashTable *shared_mappings;
  CxlMemsimV2CacheLine *cache;
  CxlMemsimV2SnoopHandler snoop_handler;
  void *snoop_opaque;
  CxlMemsimV2SharedAccessHandler shared_access_handler;
  void *shared_access_opaque;
  CxlMemsimV2SharedInvalidateHandler shared_invalidate_handler;
  void *shared_invalidate_opaque;
  CxlMemsimV2WaitServiceHandler wait_service_handler;
  void *wait_service_opaque;
  char *connection_error;
  size_t cache_line_count;
  size_t cache_set_count;
  size_t cache_resident_pages_per_set;
  size_t operation_gate_count;
  uint16_t cache_ways;
  int timeout_ms;
  uint64_t cache_clock;
  CxlMemsimV2WritePolicy write_policy;
  uint64_t capabilities;
  CxlMemsimV2ClientStats stats;
  uint64_t last_direct_page[2];
  bool last_direct_page_valid[2];
  unsigned progress_starts;
  unsigned writeback_thread_count;
  unsigned writeback_active;
  bool started;
  bool running;
  bool connected;
  bool response_ack_in_progress;
  bool progress_joinable;
  bool writeback_stop;
  bool writeback_failed;
  char *writeback_error;
};

typedef struct CxlMemsimV2OperationGuard {
  size_t first_gate;
  size_t second_gate;
  bool has_second_gate;
} CxlMemsimV2OperationGuard;

static void cxl_memsim_v2_start_writeback_workers(CxlMemsimV2Client *client);
static void cxl_memsim_v2_stop_writeback_workers(CxlMemsimV2Client *client);
static bool cxl_memsim_v2_drain_writebacks(CxlMemsimV2Client *client,
                                           Error **errp);
static bool cxl_memsim_v2_queue_writeback(CxlMemsimV2Client *client,
                                          uint64_t line_address, Error **errp);
static bool cxl_memsim_v2_bind_shared_mapping(CxlMemsimV2Client *client,
                                              uint64_t page_address,
                                              void *mapping, Error **errp);

static bool cxl_memsim_v2_invalidate_shared_mapping(
    CxlMemsimV2Client *client, const CxlMemsimV2CacheLine *line,
    CxlMemsimV2LineState new_state, Error **errp) {
  if (!line->shared_range || !client->shared_invalidate_handler) {
    return true;
  }
  if (line->resident_mask == 0) {
    return true;
  }
  if (!line->shared_mapping) {
    error_setg(errp, "missing CXLMemSim v2 shared mapping to invalidate");
    return false;
  }
  return client->shared_invalidate_handler(
      client->shared_invalidate_opaque, line->shared_mapping, line->address,
      CXL_MEMSIM_V2_SHARED_RANGE_SIZE, line->state, new_state, errp);
}

static bool
cxl_memsim_v2_shared_ranges_enabled(const CxlMemsimV2Client *client) {
  return client && (client->capabilities & CXL_MEMSIM_V2_CAP_SHARED_RANGE) != 0;
}

QEMU_BUILD_BUG_ON(sizeof(CxlMemsimV2Frame) != CXL_MEMSIM_V2_FRAME_SIZE);
QEMU_BUILD_BUG_ON(offsetof(CxlMemsimV2Frame, request_id) != 24);
QEMU_BUILD_BUG_ON(offsetof(CxlMemsimV2Frame, data) != 104);

static bool cxl_memsim_v2_is_snoop(uint16_t opcode) {
  return opcode == CXL_MEMSIM_V2_OP_SNP_INV ||
         opcode == CXL_MEMSIM_V2_OP_SNP_DOWNGRADE ||
         opcode == CXL_MEMSIM_V2_OP_SNP_DATA_INV ||
         opcode == CXL_MEMSIM_V2_OP_SNP_DATA_DOWNGRADE ||
         opcode == CXL_MEMSIM_V2_OP_HOST_FENCE;
}

static bool cxl_memsim_v2_known_opcode(uint16_t opcode) {
  switch (opcode) {
  case CXL_MEMSIM_V2_OP_REGISTER:
  case CXL_MEMSIM_V2_OP_UNREGISTER:
  case CXL_MEMSIM_V2_OP_GETS:
  case CXL_MEMSIM_V2_OP_GETM:
  case CXL_MEMSIM_V2_OP_UPGRADE:
  case CXL_MEMSIM_V2_OP_PUTS:
  case CXL_MEMSIM_V2_OP_PUTM:
  case CXL_MEMSIM_V2_OP_ATOMIC_FAA:
  case CXL_MEMSIM_V2_OP_ATOMIC_CAS:
  case CXL_MEMSIM_V2_OP_FENCE:
  case CXL_MEMSIM_V2_OP_SNOOP_ACK:
  case CXL_MEMSIM_V2_OP_HEARTBEAT:
  case CXL_MEMSIM_V2_OP_RESIDENT:
  case CXL_MEMSIM_V2_OP_RESPONSE:
  case CXL_MEMSIM_V2_OP_SNP_INV:
  case CXL_MEMSIM_V2_OP_SNP_DOWNGRADE:
  case CXL_MEMSIM_V2_OP_SNP_DATA_INV:
  case CXL_MEMSIM_V2_OP_SNP_DATA_DOWNGRADE:
  case CXL_MEMSIM_V2_OP_HOST_FENCE:
    return true;
  default:
    return false;
  }
}

static size_t cxl_memsim_v2_cache_set(const CxlMemsimV2Client *client,
                                      uint64_t line_address) {
  unsigned granule = client->capabilities & CXL_MEMSIM_V2_CAP_SHARED_RANGE
                         ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE
                         : CXL_MEMSIM_V2_LINE_SIZE;

  return (line_address / granule) % client->cache_set_count;
}

/*
 * A cache-set transaction may choose or evict any way in that set, so the set
 * is the smallest safe local serialization unit.  The reader side excludes a
 * full endpoint fence while allowing unrelated sets to issue correlated wire
 * requests concurrently.  Snoops deliberately bypass both locks: an
 * in-flight ownership request must always be able to receive its completion.
 */
static void cxl_memsim_v2_operation_begin(CxlMemsimV2Client *client,
                                          uint64_t address, unsigned size,
                                          CxlMemsimV2OperationGuard *guard) {
  unsigned granule = client->capabilities & CXL_MEMSIM_V2_CAP_SHARED_RANGE
                         ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE
                         : CXL_MEMSIM_V2_LINE_SIZE;
  uint64_t first_line = address & ~(uint64_t)(granule - 1);
  uint64_t last_line = (address + size - 1) & ~(uint64_t)(granule - 1);
  size_t first_gate;
  size_t last_gate;

  g_rw_lock_reader_lock(&client->operation_barrier);
  first_gate = cxl_memsim_v2_cache_set(client, first_line) %
               client->operation_gate_count;
  last_gate =
      cxl_memsim_v2_cache_set(client, last_line) % client->operation_gate_count;
  guard->first_gate = MIN(first_gate, last_gate);
  guard->second_gate = MAX(first_gate, last_gate);
  guard->has_second_gate = guard->first_gate != guard->second_gate;
  qemu_mutex_lock(&client->operation_gates[guard->first_gate]);
  if (guard->has_second_gate) {
    qemu_mutex_lock(&client->operation_gates[guard->second_gate]);
  }
}

static void
cxl_memsim_v2_operation_end(CxlMemsimV2Client *client,
                            const CxlMemsimV2OperationGuard *guard) {
  if (guard->has_second_gate) {
    qemu_mutex_unlock(&client->operation_gates[guard->second_gate]);
  }
  qemu_mutex_unlock(&client->operation_gates[guard->first_gate]);
  g_rw_lock_reader_unlock(&client->operation_barrier);
}

static CxlMemsimV2CacheLine *
cxl_memsim_v2_cache_find_locked(CxlMemsimV2Client *client,
                                uint64_t line_address) {
  size_t first;
  size_t way;

  if (!client->cache || !client->cache_set_count) {
    return NULL;
  }
  first = cxl_memsim_v2_cache_set(client, line_address) * client->cache_ways;
  for (way = 0; way < client->cache_ways; way++) {
    CxlMemsimV2CacheLine *line = &client->cache[first + way];

    if (line->valid && line->address == line_address) {
      return line;
    }
  }
  return NULL;
}

static CxlMemsimV2CacheLine *
cxl_memsim_v2_cache_victim_locked(CxlMemsimV2Client *client,
                                  uint64_t line_address) {
  size_t first =
      cxl_memsim_v2_cache_set(client, line_address) * client->cache_ways;
  CxlMemsimV2CacheLine *victim = NULL;
  size_t way;

  for (way = 0; way < client->cache_ways; way++) {
    CxlMemsimV2CacheLine *candidate = &client->cache[first + way];

    if (candidate->invalidating) {
      continue;
    }
    if (!candidate->valid) {
      return candidate;
    }
    if (!victim || candidate->last_used < victim->last_used) {
      victim = candidate;
    }
  }
  return victim;
}

static void cxl_memsim_v2_cache_touch_locked(CxlMemsimV2Client *client,
                                             CxlMemsimV2CacheLine *line) {
  client->cache_clock++;
  if (!client->cache_clock) {
    size_t index;

    for (index = 0; index < client->cache_line_count; index++) {
      client->cache[index].last_used = 0;
    }
    client->cache_clock = 1;
  }
  line->last_used = client->cache_clock;
}

static bool cxl_memsim_v2_cache_snoop(CxlMemsimV2Client *client,
                                      const CxlMemsimV2Frame *snoop,
                                      CxlMemsimV2Frame *ack, Error **errp) {
  typedef struct CxlMemsimV2Invalidation {
    CxlMemsimV2CacheLine *slot;
    CxlMemsimV2CacheLine snapshot;
  } CxlMemsimV2Invalidation;

  CxlMemsimV2CacheLine snapshot;
  CxlMemsimV2CacheLine *line;
  CxlMemsimV2CacheLine *slot;
  CxlMemsimV2LineState new_state = CXL_MEMSIM_V2_STATE_I;
  bool applicable = false;
  bool dirty_data = false;
  size_t index;

  qemu_mutex_lock(&client->cache_lock);
  if (snoop->type == CXL_MEMSIM_V2_OP_HOST_FENCE) {
    GArray *invalidations;

    for (index = 0; index < client->cache_line_count; index++) {
      if (client->cache[index].valid &&
          client->cache[index].state == CXL_MEMSIM_V2_STATE_M) {
        qemu_mutex_unlock(&client->cache_lock);
        return true;
      }
    }
    invalidations =
        g_array_new(false, false, sizeof(CxlMemsimV2Invalidation));
    for (index = 0; index < client->cache_line_count; index++) {
      CxlMemsimV2CacheLine *candidate = &client->cache[index];

      if (candidate->valid) {
        CxlMemsimV2Invalidation invalidation = {
            .slot = candidate,
            .snapshot = *candidate,
        };

        g_array_append_val(invalidations, invalidation);
        candidate->valid = false;
        candidate->invalidating = true;
      }
    }
    qemu_mutex_unlock(&client->cache_lock);
    for (index = 0; index < invalidations->len; index++) {
      CxlMemsimV2Invalidation *invalidation =
          &g_array_index(invalidations, CxlMemsimV2Invalidation, index);

      if (!cxl_memsim_v2_invalidate_shared_mapping(
              client, &invalidation->snapshot, CXL_MEMSIM_V2_STATE_I, errp)) {
        size_t restore;

        qemu_mutex_lock(&client->cache_lock);
        for (restore = 0; restore < invalidations->len; restore++) {
          CxlMemsimV2Invalidation *pending =
              &g_array_index(invalidations, CxlMemsimV2Invalidation, restore);

          if (pending->slot->invalidating && !pending->slot->valid) {
            *pending->slot = pending->snapshot;
          }
        }
        qemu_mutex_unlock(&client->cache_lock);
        g_array_free(invalidations, true);
        return false;
      }
    }
    qemu_mutex_lock(&client->cache_lock);
    for (index = 0; index < invalidations->len; index++) {
      CxlMemsimV2Invalidation *invalidation =
          &g_array_index(invalidations, CxlMemsimV2Invalidation, index);

      if (invalidation->slot->invalidating && !invalidation->slot->valid) {
        memset(invalidation->slot, 0, sizeof(*invalidation->slot));
      }
    }
    qemu_mutex_unlock(&client->cache_lock);
    g_array_free(invalidations, true);
    ack->status = CXL_MEMSIM_V2_STATUS_OK;
    ack->state = CXL_MEMSIM_V2_STATE_I;
    return true;
  }

  line = cxl_memsim_v2_cache_find_locked(client, snoop->addr);
  if (!line || snoop->epoch <= line->epoch) {
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }
  if (line->shared_range != (snoop->size == CXL_MEMSIM_V2_SHARED_RANGE_SIZE)) {
    qemu_mutex_unlock(&client->cache_lock);
    error_setg(errp, "CXLMemSim v2 snoop granularity mismatch");
    return false;
  }
  switch (snoop->type) {
  case CXL_MEMSIM_V2_OP_SNP_INV:
    if (line->state != CXL_MEMSIM_V2_STATE_S &&
        line->state != CXL_MEMSIM_V2_STATE_E) {
      break;
    }
    new_state = CXL_MEMSIM_V2_STATE_I;
    applicable = true;
    break;
  case CXL_MEMSIM_V2_OP_SNP_DOWNGRADE:
    if (line->state != CXL_MEMSIM_V2_STATE_E) {
      break;
    }
    new_state = CXL_MEMSIM_V2_STATE_S;
    applicable = true;
    break;
  case CXL_MEMSIM_V2_OP_SNP_DATA_INV:
  case CXL_MEMSIM_V2_OP_SNP_DATA_DOWNGRADE:
    if (line->state != CXL_MEMSIM_V2_STATE_M) {
      break;
    }
    new_state = snoop->type == CXL_MEMSIM_V2_OP_SNP_DATA_INV
                    ? CXL_MEMSIM_V2_STATE_I
                    : CXL_MEMSIM_V2_STATE_S;
    applicable = true;
    dirty_data = true;
    break;
  default:
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }

  if (!applicable) {
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }

  if (!line->shared_range) {
    if (dirty_data) {
      ack->payload_len = CXL_MEMSIM_V2_LINE_SIZE;
      memcpy(ack->data, line->data, sizeof(ack->data));
    }
    line->dirty = false;
    line->writable_mask = 0;
    line->epoch = snoop->epoch;
    if (new_state == CXL_MEMSIM_V2_STATE_I) {
      line->valid = false;
      line->resident_mask = 0;
    }
    line->state = new_state;
    ack->status = CXL_MEMSIM_V2_STATUS_OK;
    ack->state = new_state;
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }

  /*
   * A TCG notifier flush can wait for any vCPU.  Reserve the grant under the
   * cache lock, then drop that lock before waiting: a target vCPU may itself
   * be in a direct-map miss path that briefly needs cache_lock.  valid=false
   * prevents any new local access from using the old grant, while
   * invalidating=true keeps its slot from being reused until the flush and
   * snoop data capture are complete.  The server does not issue the new grant
   * until this ACK, so a refault can only queue behind this transition.
   */
  snapshot = *line;
  slot = line;
  slot->valid = false;
  slot->invalidating = true;
  qemu_mutex_unlock(&client->cache_lock);

  if (!cxl_memsim_v2_invalidate_shared_mapping(client, &snapshot, new_state,
                                               errp)) {
    goto restore_shared_grant;
  }
  /* The completed TLB invalidation is the store-to-ACK ordering point. */
  smp_mb();
  if (dirty_data) {
    ack->payload_len = CXL_MEMSIM_V2_LINE_SIZE;
    if (!client->shared_access_handler || !snapshot.shared_mapping ||
        !client->shared_access_handler(
            client->shared_access_opaque, snapshot.shared_mapping,
            snapshot.address, ack->data, sizeof(ack->data), false, errp)) {
      ack->payload_len = 0;
      goto restore_shared_grant;
    }
  }

  qemu_mutex_lock(&client->cache_lock);
  if (!slot->invalidating || slot->valid ||
      slot->address != snapshot.address || slot->epoch != snapshot.epoch) {
    qemu_mutex_unlock(&client->cache_lock);
    error_setg(errp, "CXLMemSim v2 shared grant reservation changed");
    return false;
  }
  if (new_state == CXL_MEMSIM_V2_STATE_I) {
    memset(slot, 0, sizeof(*slot));
  } else {
    *slot = snapshot;
    slot->state = CXL_MEMSIM_V2_STATE_S;
    slot->epoch = snoop->epoch;
    slot->dirty = false;
    slot->writable_mask = 0;
    slot->invalidating = false;
    slot->valid = true;
  }
  qemu_mutex_unlock(&client->cache_lock);
  ack->status = CXL_MEMSIM_V2_STATUS_OK;
  ack->state = new_state;
  return true;

restore_shared_grant:
  qemu_mutex_lock(&client->cache_lock);
  if (slot->invalidating && !slot->valid &&
      slot->address == snapshot.address && slot->epoch == snapshot.epoch) {
    *slot = snapshot;
  }
  qemu_mutex_unlock(&client->cache_lock);
  return false;
}

void cxl_memsim_v2_frame_init(CxlMemsimV2Frame *frame,
                              CxlMemsimV2Opcode opcode) {
  memset(frame, 0, sizeof(*frame));
  frame->magic = CXL_MEMSIM_V2_MAGIC;
  frame->version = CXL_MEMSIM_V2_VERSION;
  frame->type = opcode;
}

void cxl_memsim_v2_encode_frame(const CxlMemsimV2Frame *frame,
                                uint8_t bytes[CXL_MEMSIM_V2_FRAME_SIZE]) {
  memset(bytes, 0, CXL_MEMSIM_V2_FRAME_SIZE);
  stl_le_p(bytes + 0, frame->magic);
  stw_le_p(bytes + 4, frame->version);
  stw_le_p(bytes + 6, frame->type);
  stl_le_p(bytes + 8, frame->flags);
  stw_le_p(bytes + 12, frame->status);
  bytes[14] = frame->ack_strength;
  bytes[15] = frame->state;
  stw_le_p(bytes + 16, frame->src_host);
  stw_le_p(bytes + 18, frame->dst_host);
  stw_le_p(bytes + 20, frame->payload_len);
  stw_le_p(bytes + 22, frame->reserved0);
  stq_le_p(bytes + 24, frame->request_id);
  stq_le_p(bytes + 32, frame->snoop_id);
  stq_le_p(bytes + 40, frame->session_id);
  stq_le_p(bytes + 48, frame->addr);
  stq_le_p(bytes + 56, frame->epoch);
  stq_le_p(bytes + 64, frame->capabilities);
  stq_le_p(bytes + 72, frame->expected);
  stq_le_p(bytes + 80, frame->value);
  stq_le_p(bytes + 88, frame->old_value);
  stl_le_p(bytes + 96, frame->size);
  stl_le_p(bytes + 100, frame->reserved1);
  memcpy(bytes + 104, frame->data, sizeof(frame->data));
  memcpy(bytes + 168, frame->reserved, sizeof(frame->reserved));
}

static bool cxl_memsim_v2_frames_equal(const CxlMemsimV2Frame *left,
                                       const CxlMemsimV2Frame *right) {
  uint8_t left_bytes[CXL_MEMSIM_V2_FRAME_SIZE];
  uint8_t right_bytes[CXL_MEMSIM_V2_FRAME_SIZE];

  cxl_memsim_v2_encode_frame(left, left_bytes);
  cxl_memsim_v2_encode_frame(right, right_bytes);
  return memcmp(left_bytes, right_bytes, sizeof(left_bytes)) == 0;
}

bool cxl_memsim_v2_decode_frame(const uint8_t bytes[CXL_MEMSIM_V2_FRAME_SIZE],
                                CxlMemsimV2Frame *frame, Error **errp) {
  CxlMemsimV2Frame decoded = {
      .magic = ldl_le_p(bytes + 0),
      .version = lduw_le_p(bytes + 4),
      .type = lduw_le_p(bytes + 6),
      .flags = ldl_le_p(bytes + 8),
      .status = lduw_le_p(bytes + 12),
      .ack_strength = bytes[14],
      .state = bytes[15],
      .src_host = lduw_le_p(bytes + 16),
      .dst_host = lduw_le_p(bytes + 18),
      .payload_len = lduw_le_p(bytes + 20),
      .reserved0 = lduw_le_p(bytes + 22),
      .request_id = ldq_le_p(bytes + 24),
      .snoop_id = ldq_le_p(bytes + 32),
      .session_id = ldq_le_p(bytes + 40),
      .addr = ldq_le_p(bytes + 48),
      .epoch = ldq_le_p(bytes + 56),
      .capabilities = ldq_le_p(bytes + 64),
      .expected = ldq_le_p(bytes + 72),
      .value = ldq_le_p(bytes + 80),
      .old_value = ldq_le_p(bytes + 88),
      .size = ldl_le_p(bytes + 96),
      .reserved1 = ldl_le_p(bytes + 100),
  };
  size_t i;

  memcpy(decoded.data, bytes + 104, sizeof(decoded.data));
  memcpy(decoded.reserved, bytes + 168, sizeof(decoded.reserved));
  if (decoded.magic != CXL_MEMSIM_V2_MAGIC ||
      decoded.version != CXL_MEMSIM_V2_VERSION ||
      !cxl_memsim_v2_known_opcode(decoded.type) || decoded.flags ||
      decoded.status > CXL_MEMSIM_V2_STATUS_IO_ERROR ||
      decoded.ack_strength > CXL_MEMSIM_V2_ACK_NATIVE ||
      decoded.state > CXL_MEMSIM_V2_STATE_M ||
      decoded.payload_len > CXL_MEMSIM_V2_LINE_SIZE || decoded.reserved0 ||
      decoded.reserved1) {
    error_setg(errp, "invalid CXLMemSim v2 frame envelope");
    return false;
  }
  for (i = decoded.payload_len; i < sizeof(decoded.data); i++) {
    if (decoded.data[i]) {
      error_setg(errp, "nonzero unused CXLMemSim v2 payload");
      return false;
    }
  }
  for (i = 0; i < sizeof(decoded.reserved); i++) {
    if (decoded.reserved[i]) {
      error_setg(errp, "nonzero CXLMemSim v2 reserved bytes");
      return false;
    }
  }
  *frame = decoded;
  return true;
}

static void cxl_memsim_v2_fail_connection_locked(CxlMemsimV2Client *client,
                                                 const char *message) {
  GHashTableIter iter;
  gpointer value;

  client->connected = false;
  g_free(client->connection_error);
  client->connection_error = g_strdup(message);
  g_hash_table_iter_init(&iter, client->pending);
  while (g_hash_table_iter_next(&iter, NULL, &value)) {
    CxlMemsimV2Pending *pending = value;

    pending->io_failed = true;
    pending->done = true;
    qemu_cond_signal(&pending->completed);
  }
}

static void cxl_memsim_v2_fail_connection(CxlMemsimV2Client *client,
                                          const char *message) {
  qemu_mutex_lock(&client->state_lock);
  cxl_memsim_v2_fail_connection_locked(client, message);
  qemu_mutex_unlock(&client->state_lock);
}

static void cxl_memsim_v2_disconnect(CxlMemsimV2Client *client,
                                     const char *message) {
  cxl_memsim_v2_fail_connection(client, message);
  if (client->socket) {
    qio_channel_shutdown(QIO_CHANNEL(client->socket), QIO_CHANNEL_SHUTDOWN_BOTH,
                         NULL);
  }
}

static bool cxl_memsim_v2_write_frame(CxlMemsimV2Client *client,
                                      const CxlMemsimV2Frame *frame,
                                      Error **errp) {
  uint8_t bytes[CXL_MEMSIM_V2_FRAME_SIZE];
  int result;

  cxl_memsim_v2_encode_frame(frame, bytes);
  qemu_mutex_lock(&client->send_lock);
  result = qio_channel_write_all(QIO_CHANNEL(client->socket),
                                 (const char *)bytes, sizeof(bytes), errp);
  qemu_mutex_unlock(&client->send_lock);
  return result == 0;
}

static bool cxl_memsim_v2_validate_response(CxlMemsimV2Client *client,
                                            const CxlMemsimV2Frame *request,
                                            const CxlMemsimV2Frame *response) {
  if (response->type != CXL_MEMSIM_V2_OP_RESPONSE ||
      response->src_host != CXL_MEMSIM_V2_SERVER_ENDPOINT ||
      response->dst_host != client->endpoint ||
      response->request_id != request->request_id || response->snoop_id ||
      response->addr != request->addr) {
    return false;
  }
  if (request->type == CXL_MEMSIM_V2_OP_REGISTER) {
    return response->status == CXL_MEMSIM_V2_STATUS_OK
               ? response->session_id != 0
               : response->session_id == request->session_id;
  }
  return response->session_id == request->session_id &&
         response->session_id != 0;
}

static bool cxl_memsim_v2_send_snoop_ack(CxlMemsimV2Client *client,
                                         const CxlMemsimV2Frame *snoop) {
  CxlMemsimV2Frame ack;
  Error *local_err = NULL;
  bool handled = false;

  cxl_memsim_v2_frame_init(&ack, CXL_MEMSIM_V2_OP_SNOOP_ACK);
  ack.status = CXL_MEMSIM_V2_STATUS_INVALID_STATE;
  ack.ack_strength = CXL_MEMSIM_V2_ACK_MODEL;
  ack.state = CXL_MEMSIM_V2_STATE_I;
  ack.src_host = client->endpoint;
  ack.dst_host = CXL_MEMSIM_V2_SERVER_ENDPOINT;
  ack.snoop_id = snoop->snoop_id;
  ack.session_id = client->session_id;
  ack.addr = snoop->addr;
  ack.epoch = snoop->epoch;
  ack.size = snoop->size;
  if (client->snoop_handler) {
    handled =
        client->snoop_handler(client->snoop_opaque, snoop, &ack, &local_err);
  }
  if (!handled && !local_err) {
    handled = cxl_memsim_v2_cache_snoop(client, snoop, &ack, &local_err);
  }
  if (local_err) {
    error_report_err(local_err);
    return false;
  }
  if (ack.payload_len > CXL_MEMSIM_V2_LINE_SIZE ||
      !cxl_memsim_v2_write_frame(client, &ack, &local_err)) {
    if (local_err) {
      error_report_err(local_err);
    }
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_install_grant(CxlMemsimV2Client *client,
                                        const CxlMemsimV2Frame *request,
                                        const CxlMemsimV2Frame *response) {
  CxlMemsimV2CacheLine *line;
  uint64_t line_address;
  void *shared_mapping = NULL;
  bool acquire;
  bool shared_range;
  uint64_t resident_mask = 0;
  uint64_t writable_mask = 0;

  if (response->status != CXL_MEMSIM_V2_STATUS_OK) {
    return true;
  }
  acquire = request->type == CXL_MEMSIM_V2_OP_GETS ||
            request->type == CXL_MEMSIM_V2_OP_GETM ||
            request->type == CXL_MEMSIM_V2_OP_ATOMIC_FAA ||
            request->type == CXL_MEMSIM_V2_OP_ATOMIC_CAS;
  if (!acquire && request->type != CXL_MEMSIM_V2_OP_UPGRADE) {
    return true;
  }
  shared_range = request->size == CXL_MEMSIM_V2_SHARED_RANGE_SIZE;
  if (shared_range) {
    resident_mask =
        request->value ? request->value : CXL_MEMSIM_V2_RESIDENCY_FULL_MASK;
    if (request->type == CXL_MEMSIM_V2_OP_GETM ||
        request->type == CXL_MEMSIM_V2_OP_UPGRADE) {
      writable_mask = request->value ? request->expected
                                     : CXL_MEMSIM_V2_RESIDENCY_FULL_MASK;
    }
    if (response->value != request->value ||
        response->expected != request->expected) {
      return false;
    }
  }
  line_address = request->addr &
                 ~(uint64_t)((shared_range ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE
                                           : CXL_MEMSIM_V2_LINE_SIZE) -
                             1);
  qemu_mutex_lock(&client->cache_lock);
  if (request->type == CXL_MEMSIM_V2_OP_UPGRADE ||
      (request->type == CXL_MEMSIM_V2_OP_GETM &&
       request->state == CXL_MEMSIM_V2_STATE_M)) {
    line = cxl_memsim_v2_cache_find_locked(client, line_address);
    if (!line || response->state != CXL_MEMSIM_V2_STATE_M ||
        response->epoch <= line->epoch || response->payload_len ||
        response->size !=
            (shared_range ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE : 0) ||
        line->shared_range != shared_range ||
        (shared_range && !line->shared_mapping)) {
      qemu_mutex_unlock(&client->cache_lock);
      return false;
    }
    line->state = CXL_MEMSIM_V2_STATE_M;
    line->epoch = response->epoch;
    /* A shared M grant can be exposed as a writable TCG mapping immediately
     * after this response.  Conservatively arm its dirty attribution now;
     * Fence clears it only after persistence and TLB invalidation. */
    if (shared_range) {
      line->resident_mask |= resident_mask;
      line->writable_mask |= writable_mask;
      line->dirty = line->writable_mask != 0;
    }
    cxl_memsim_v2_cache_touch_locked(client, line);
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }
  if (shared_range) {
    shared_mapping =
        g_hash_table_lookup(client->shared_mappings, &line_address);
    if (!shared_mapping) {
      qemu_mutex_unlock(&client->cache_lock);
      return false;
    }
  }
  if (response->payload_len != (shared_range ? 0 : CXL_MEMSIM_V2_LINE_SIZE) ||
      response->size != (shared_range ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE : 0) ||
      !response->epoch ||
      (request->type == CXL_MEMSIM_V2_OP_GETS
           ? response->state != CXL_MEMSIM_V2_STATE_S &&
                 response->state != CXL_MEMSIM_V2_STATE_E
           : response->state != CXL_MEMSIM_V2_STATE_M)) {
    qemu_mutex_unlock(&client->cache_lock);
    return false;
  }
  line = cxl_memsim_v2_cache_find_locked(client, line_address);
  if (!line) {
    line = cxl_memsim_v2_cache_victim_locked(client, line_address);
  }
  if (!line || (line->valid && line->address != line_address)) {
    qemu_mutex_unlock(&client->cache_lock);
    return false;
  }
  memset(line, 0, sizeof(*line));
  line->address = line_address;
  line->epoch = response->epoch;
  line->state = response->state;
  line->valid = true;
  line->shared_range = shared_range;
  line->shared_mapping = shared_mapping;
  if (shared_range && response->state == CXL_MEMSIM_V2_STATE_M) {
    line->resident_mask = resident_mask;
    line->writable_mask = writable_mask;
    line->dirty = line->writable_mask != 0;
  } else if (shared_range) {
    line->resident_mask = resident_mask;
  }
  if (shared_range) {
    g_hash_table_remove(client->shared_mappings, &line_address);
  }
  if (!shared_range) {
    memcpy(line->data, response->data, sizeof(line->data));
  }
  cxl_memsim_v2_cache_touch_locked(client, line);
  qemu_mutex_unlock(&client->cache_lock);
  return true;
}

static void *cxl_memsim_v2_progress(void *opaque) {
  CxlMemsimV2Client *client = opaque;
  uint8_t bytes[CXL_MEMSIM_V2_FRAME_SIZE];

  qemu_mutex_lock(&client->state_lock);
  client->progress_starts++;
  qemu_mutex_unlock(&client->state_lock);

  for (;;) {
    CxlMemsimV2Frame frame;
    CxlMemsimV2Pending *pending;
    Error *local_err = NULL;

    if (qio_channel_read_all(QIO_CHANNEL(client->socket), (char *)bytes,
                             sizeof(bytes), &local_err) < 0) {
      const char *message =
          local_err ? error_get_pretty(local_err) : "CXLMemSim v2 read failed";

      cxl_memsim_v2_fail_connection(client, message);
      error_free(local_err);
      break;
    }
    if (!cxl_memsim_v2_decode_frame(bytes, &frame, &local_err)) {
      const char *message = error_get_pretty(local_err);

      cxl_memsim_v2_fail_connection(client, message);
      error_free(local_err);
      break;
    }
    if (frame.type == CXL_MEMSIM_V2_OP_RESPONSE) {
      CxlMemsimV2Frame *completed;

      qemu_mutex_lock(&client->state_lock);
      pending = g_hash_table_lookup(client->pending, &frame.request_id);
      if (!pending) {
        completed =
            g_hash_table_lookup(client->completed_retries, &frame.request_id);
        if (completed && cxl_memsim_v2_frames_equal(completed, &frame)) {
          qemu_mutex_unlock(&client->state_lock);
          continue;
        }
        qemu_mutex_unlock(&client->state_lock);
        cxl_memsim_v2_fail_connection(client,
                                      "uncorrelated CXLMemSim v2 response");
        break;
      }
      if (!cxl_memsim_v2_validate_response(client, &pending->request, &frame)) {
        qemu_mutex_unlock(&client->state_lock);
        cxl_memsim_v2_fail_connection(client,
                                      "uncorrelated CXLMemSim v2 response");
        break;
      }
      if (pending->done) {
        if (pending->retried &&
            cxl_memsim_v2_frames_equal(&pending->response, &frame)) {
          qemu_mutex_unlock(&client->state_lock);
          continue;
        }
        qemu_mutex_unlock(&client->state_lock);
        cxl_memsim_v2_fail_connection(
            client, "conflicting CXLMemSim v2 duplicate response");
        break;
      }
      if (!cxl_memsim_v2_install_grant(client, &pending->request, &frame)) {
        qemu_mutex_unlock(&client->state_lock);
        cxl_memsim_v2_fail_connection(
            client, "invalid or unreserved CXLMemSim v2 grant");
        break;
      }
      pending->response = frame;
      pending->done = true;
      qemu_cond_signal(&pending->completed);
      qemu_mutex_unlock(&client->state_lock);
      continue;
    }
    if (!cxl_memsim_v2_is_snoop(frame.type) ||
        frame.src_host != CXL_MEMSIM_V2_SERVER_ENDPOINT ||
        frame.dst_host != client->endpoint ||
        frame.session_id != client->session_id || !frame.snoop_id ||
        !cxl_memsim_v2_send_snoop_ack(client, &frame)) {
      cxl_memsim_v2_fail_connection(
          client, "invalid CXLMemSim v2 snoop or ACK failure");
      break;
    }
  }

  qemu_mutex_lock(&client->state_lock);
  client->running = false;
  qemu_mutex_unlock(&client->state_lock);
  return NULL;
}

CxlMemsimV2Client *
cxl_memsim_v2_client_new(uint16_t endpoint,
                         CxlMemsimV2SnoopHandler snoop_handler,
                         void *snoop_opaque) {
  CxlMemsimV2Client *client;
  size_t index;

  if (endpoint >= CXL_MEMSIM_V2_MAX_ENDPOINTS) {
    return NULL;
  }
  client = g_new0(CxlMemsimV2Client, 1);
  client->endpoint = endpoint;
  client->next_request_id = 1;
  client->write_policy = CXL_MEMSIM_V2_WRITE_BACK;
  client->snoop_handler = snoop_handler;
  client->snoop_opaque = snoop_opaque;
  client->pending = g_hash_table_new(g_int64_hash, g_int64_equal);
  client->completed_retries =
      g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
  client->shared_mappings =
      g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
  client->writeback_pending =
      g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
  g_queue_init(&client->writeback_queue);
  client->operation_gate_count = CXL_MEMSIM_V2_OPERATION_GATE_COUNT;
  client->operation_gates = g_new0(QemuMutex, client->operation_gate_count);
  qemu_mutex_init(&client->state_lock);
  qemu_mutex_init(&client->request_lock);
  qemu_mutex_init(&client->send_lock);
  g_rw_lock_init(&client->operation_barrier);
  for (index = 0; index < client->operation_gate_count; index++) {
    qemu_mutex_init(&client->operation_gates[index]);
  }
  qemu_mutex_init(&client->cache_lock);
  qemu_mutex_init(&client->writeback_lock);
  qemu_cond_init(&client->writeback_available);
  qemu_cond_init(&client->writeback_drained);
  return client;
}

bool cxl_memsim_v2_client_set_write_policy(CxlMemsimV2Client *client,
                                           CxlMemsimV2WritePolicy policy,
                                           Error **errp) {
  if (!client || (policy != CXL_MEMSIM_V2_WRITE_BACK &&
                  policy != CXL_MEMSIM_V2_WRITE_THROUGH)) {
    error_setg(errp, "invalid CXLMemSim v2 write policy");
    return false;
  }
  qemu_mutex_lock(&client->state_lock);
  if (client->started) {
    qemu_mutex_unlock(&client->state_lock);
    error_setg(errp, "CXLMemSim v2 write policy is already active");
    return false;
  }
  client->write_policy = policy;
  qemu_mutex_unlock(&client->state_lock);
  return true;
}

bool cxl_memsim_v2_client_set_shared_access(
    CxlMemsimV2Client *client, CxlMemsimV2SharedAccessHandler handler,
    void *opaque, Error **errp) {
  if (!client || !handler) {
    error_setg(errp, "invalid CXLMemSim v2 shared access handler");
    return false;
  }
  qemu_mutex_lock(&client->state_lock);
  if (client->started) {
    qemu_mutex_unlock(&client->state_lock);
    error_setg(errp, "CXLMemSim v2 shared access is already active");
    return false;
  }
  client->shared_access_handler = handler;
  client->shared_access_opaque = opaque;
  qemu_mutex_unlock(&client->state_lock);
  return true;
}

bool cxl_memsim_v2_client_set_shared_invalidate(
    CxlMemsimV2Client *client, CxlMemsimV2SharedInvalidateHandler handler,
    void *opaque, Error **errp) {
  if (!client || !handler) {
    error_setg(errp, "invalid CXLMemSim v2 shared invalidation handler");
    return false;
  }
  qemu_mutex_lock(&client->state_lock);
  if (client->started) {
    qemu_mutex_unlock(&client->state_lock);
    error_setg(errp, "CXLMemSim v2 shared invalidation is already active");
    return false;
  }
  client->shared_invalidate_handler = handler;
  client->shared_invalidate_opaque = opaque;
  qemu_mutex_unlock(&client->state_lock);
  return true;
}

bool cxl_memsim_v2_client_set_wait_service(
    CxlMemsimV2Client *client, CxlMemsimV2WaitServiceHandler handler,
    void *opaque, Error **errp) {
  if (!client || !handler) {
    error_setg(errp, "invalid CXLMemSim v2 wait service handler");
    return false;
  }
  qemu_mutex_lock(&client->state_lock);
  if (client->wait_service_handler &&
      (client->wait_service_handler != handler ||
       client->wait_service_opaque != opaque)) {
    qemu_mutex_unlock(&client->state_lock);
    error_setg(errp, "CXLMemSim v2 wait service handler is already set");
    return false;
  }
  client->wait_service_handler = handler;
  client->wait_service_opaque = opaque;
  qemu_mutex_unlock(&client->state_lock);
  return true;
}

static bool cxl_memsim_v2_transact_internal(CxlMemsimV2Client *client,
                                            CxlMemsimV2Frame *request,
                                            CxlMemsimV2Frame *response,
                                            int timeout_ms, bool registration,
                                            Error **errp) {
  CxlMemsimV2Pending pending = {
      .request = *request,
  };
  int64_t deadline_us;
  unsigned attempt;
  bool success = false;
  bool disconnect = false;
  bool request_locked = false;

  if (!client || !request || !response || timeout_ms <= 0) {
    error_setg(errp, "invalid CXLMemSim v2 transaction arguments");
    return false;
  }
  qemu_cond_init(&pending.completed);
  /*
   * The server admits ordinary request IDs in wire order. Keep allocation
   * and the first write in one short critical section, but release it before
   * waiting so independent transactions can remain in flight together.
   */
  qemu_mutex_lock(&client->request_lock);
  request_locked = true;
  qemu_mutex_lock(&client->state_lock);
  if (!client->connected) {
    error_setg(errp, "%s",
               client->connection_error
                   ?: "CXLMemSim v2 client is disconnected");
    goto out_locked;
  }
  if (registration) {
    pending.request_id = 0;
  } else {
    if (!client->session_id || !client->next_request_id ||
        client->next_request_id == UINT64_MAX) {
      error_setg(errp, "CXLMemSim v2 session or request ID unavailable");
      goto out_locked;
    }
    pending.request_id = client->next_request_id++;
    request->session_id = client->session_id;
  }
  request->magic = CXL_MEMSIM_V2_MAGIC;
  request->version = CXL_MEMSIM_V2_VERSION;
  request->src_host = client->endpoint;
  request->dst_host = CXL_MEMSIM_V2_SERVER_ENDPOINT;
  request->request_id = pending.request_id;
  pending.request = *request;
  if (g_hash_table_contains(client->pending, &pending.request_id)) {
    error_setg(errp, "duplicate CXLMemSim v2 pending request");
    goto out_locked;
  }
  g_hash_table_insert(client->pending, &pending.request_id, &pending);
  qemu_mutex_unlock(&client->state_lock);

  if (!cxl_memsim_v2_write_frame(client, request, errp)) {
    qemu_mutex_unlock(&client->request_lock);
    request_locked = false;
    cxl_memsim_v2_fail_connection(client, "CXLMemSim v2 frame write failed");
    qemu_mutex_lock(&client->state_lock);
    goto remove_locked;
  }
  qemu_mutex_unlock(&client->request_lock);
  request_locked = false;

  qemu_mutex_lock(&client->state_lock);
  for (attempt = 0; attempt < 2 && !pending.done; attempt++) {
    deadline_us = g_get_monotonic_time() + timeout_ms * G_TIME_SPAN_MILLISECOND;
    while (!pending.done) {
      int64_t remaining_us = deadline_us - g_get_monotonic_time();
      int remaining_ms;
      CxlMemsimV2WaitServiceHandler wait_service = client->wait_service_handler;
      void *wait_service_opaque = client->wait_service_opaque;

      if (remaining_us <= 0) {
        break;
      }
      remaining_ms = DIV_ROUND_UP(remaining_us, G_TIME_SPAN_MILLISECOND);
      if (wait_service) {
        remaining_ms = MIN(remaining_ms, CXL_MEMSIM_V2_CPU_WORK_POLL_MS);
      }
      if (!qemu_cond_timedwait(&pending.completed, &client->state_lock,
                               remaining_ms) &&
          !pending.done && !wait_service) {
        break;
      }
      if (wait_service && !pending.done) {
        qemu_mutex_unlock(&client->state_lock);
        wait_service(wait_service_opaque);
        qemu_mutex_lock(&client->state_lock);
      }
    }
    if (!pending.done && attempt == 0) {
      Error *retry_err = NULL;
      bool retry_sent;

      pending.retried = true;
      qemu_mutex_unlock(&client->state_lock);
      retry_sent =
          cxl_memsim_v2_write_frame(client, &pending.request, &retry_err);
      qemu_mutex_lock(&client->state_lock);
      if (!retry_sent) {
        const char *message = retry_err ? error_get_pretty(retry_err)
                                        : "CXLMemSim v2 retry write failed";
        bool completed = !registration && pending.done && !pending.io_failed;

        cxl_memsim_v2_fail_connection_locked(client, message);
        if (completed) {
          pending.io_failed = false;
        }
        error_free(retry_err);
        disconnect = true;
      }
    }
  }
  if (!pending.done) {
    cxl_memsim_v2_fail_connection_locked(
        client, "CXLMemSim v2 request timed out ambiguously");
    error_setg(errp, "CXLMemSim v2 request timed out ambiguously");
    disconnect = true;
  } else if (pending.io_failed) {
    error_setg(errp, "%s",
               client->connection_error ?: "CXLMemSim v2 connection failed");
  } else {
    *response = pending.response;
    success = true;
  }

remove_locked:
  if (success && pending.retried) {
    uint64_t *request_id = g_new(uint64_t, 1);
    CxlMemsimV2Frame *completed = g_new(CxlMemsimV2Frame, 1);

    *request_id = pending.request_id;
    *completed = pending.response;
    g_hash_table_replace(client->completed_retries, request_id, completed);
  }
  g_hash_table_remove(client->pending, &pending.request_id);
out_locked:
  qemu_mutex_unlock(&client->state_lock);
  if (request_locked) {
    qemu_mutex_unlock(&client->request_lock);
  }
  qemu_cond_destroy(&pending.completed);
  if (disconnect) {
    qio_channel_shutdown(QIO_CHANNEL(client->socket), QIO_CHANNEL_SHUTDOWN_BOTH,
                         NULL);
  }
  return success;
}

bool cxl_memsim_v2_client_start_fd(CxlMemsimV2Client *client, int fd,
                                   uint32_t cache_capacity, uint16_t cache_ways,
                                   int timeout_ms, Error **errp) {
  CxlMemsimV2Frame request;
  CxlMemsimV2Frame response;
  Error *local_err = NULL;

  const uint32_t cache_granule = client && client->shared_access_handler
                                     ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE
                                     : CXL_MEMSIM_V2_LINE_SIZE;

  if (!client || fd < 0 || cache_capacity < cache_granule ||
      cache_capacity % cache_granule || !cache_ways ||
      (cache_capacity / cache_granule) % cache_ways) {
    if (fd >= 0) {
      close(fd);
    }
    error_setg(errp, "invalid CXLMemSim v2 registration geometry");
    return false;
  }
  qemu_mutex_lock(&client->state_lock);
  if (client->started) {
    qemu_mutex_unlock(&client->state_lock);
    close(fd);
    error_setg(errp, "CXLMemSim v2 client is already started");
    return false;
  }
  client->socket = qio_channel_socket_new_fd(fd, &local_err);
  if (!client->socket) {
    qemu_mutex_unlock(&client->state_lock);
    error_propagate(errp, local_err);
    return false;
  }
  /* MESI request, response, and snoop frames are latency-sensitive and small.
   * Nagle combined with the peer's delayed ACK otherwise adds recurring
   * ~40 ms stalls to an otherwise local control-plane round trip. */
  qio_channel_set_delay(QIO_CHANNEL(client->socket), false);
  if (client->shared_access_handler) {
    const size_t resident_page_count =
        cache_capacity / CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE;
    const size_t resident_range_count =
        cache_capacity / CXL_MEMSIM_V2_SHARED_RANGE_SIZE;

    client->cache_set_count = resident_range_count / cache_ways;
    client->cache_resident_pages_per_set =
        resident_page_count / client->cache_set_count;
    /* A permission entry consumes metadata for one 64 KiB range but only its
     * populated 4 KiB pages consume the endpoint residency budget. Keep one
     * metadata way per possible resident page in the set; residency trimming
     * below independently enforces the byte capacity. */
    client->cache_ways = client->cache_resident_pages_per_set;
    client->cache_line_count = client->cache_set_count * client->cache_ways;
  } else {
    client->cache_line_count = cache_capacity / cache_granule;
    client->cache_set_count = client->cache_line_count / cache_ways;
    client->cache_resident_pages_per_set = 0;
    client->cache_ways = cache_ways;
  }
  client->timeout_ms = timeout_ms;
  client->cache = g_new0(CxlMemsimV2CacheLine, client->cache_line_count);
  client->started = true;
  client->running = true;
  client->connected = true;
  qemu_mutex_unlock(&client->state_lock);

  qemu_thread_create(&client->progress_thread, "cxl-memsim-v2",
                     cxl_memsim_v2_progress, client, QEMU_THREAD_JOINABLE);
  qemu_mutex_lock(&client->state_lock);
  client->progress_joinable = true;
  qemu_mutex_unlock(&client->state_lock);

  cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_REGISTER);
  request.capabilities =
      CXL_MEMSIM_V2_CAP_MODEL_SNOOP |
      (client->shared_access_handler ? CXL_MEMSIM_V2_CAP_SHARED_RANGE : 0);
  request.expected = cache_ways;
  request.value = cache_capacity;
  request.size = CXL_MEMSIM_V2_LINE_SIZE;
  if (!cxl_memsim_v2_transact_internal(client, &request, &response, timeout_ms,
                                       true, &local_err)) {
    goto fail;
  }
  if (response.status != CXL_MEMSIM_V2_STATUS_OK ||
      response.ack_strength != CXL_MEMSIM_V2_ACK_MODEL ||
      !(response.capabilities & CXL_MEMSIM_V2_CAP_MODEL_SNOOP) ||
      (response.capabilities & ~request.capabilities) ||
      (response.capabilities &
       ~(CXL_MEMSIM_V2_CAP_MODEL_SNOOP | CXL_MEMSIM_V2_CAP_SHARED_RANGE)) ||
      response.size != CXL_MEMSIM_V2_LINE_SIZE ||
      response.value != cache_capacity || response.expected != cache_ways ||
      !response.old_value) {
    error_setg(&local_err, "CXLMemSim v2 registration response is invalid");
    goto fail;
  }
  qemu_mutex_lock(&client->state_lock);
  if (!client->connected) {
    error_setg(&local_err, "%s",
               client->connection_error
                   ?: "CXLMemSim v2 registration disconnected");
    qemu_mutex_unlock(&client->state_lock);
    goto fail;
  }
  client->session_id = response.session_id;
  client->capabilities = response.capabilities;
  qemu_mutex_unlock(&client->state_lock);
  cxl_memsim_v2_start_writeback_workers(client);
  return true;

fail:
  qio_channel_shutdown(QIO_CHANNEL(client->socket), QIO_CHANNEL_SHUTDOWN_BOTH,
                       NULL);
  qemu_thread_join(&client->progress_thread);
  qemu_mutex_lock(&client->state_lock);
  client->progress_joinable = false;
  client->running = false;
  client->connected = false;
  qemu_mutex_unlock(&client->state_lock);
  error_propagate(errp, local_err);
  return false;
}

bool cxl_memsim_v2_client_connect(CxlMemsimV2Client *client, const char *host,
                                  uint16_t port, uint32_t cache_capacity,
                                  uint16_t cache_ways, int timeout_ms,
                                  Error **errp) {
  SocketAddress address = {
      .type = SOCKET_ADDRESS_TYPE_INET,
  };
  QIOChannelSocket *socket;
  Error *local_err = NULL;
  int fd;

  if (!host || !host[0] || !port) {
    error_setg(errp, "invalid CXLMemSim v2 TCP address");
    return false;
  }
  address.u.inet.host = (char *)host;
  address.u.inet.port = g_strdup_printf("%u", port);
  socket = qio_channel_socket_new();
  if (qio_channel_socket_connect_sync(socket, &address, &local_err) < 0) {
    object_unref(OBJECT(socket));
    g_free(address.u.inet.port);
    error_propagate(errp, local_err);
    return false;
  }
  fd = dup(socket->fd);
  object_unref(OBJECT(socket));
  g_free(address.u.inet.port);
  if (fd < 0) {
    error_setg_errno(errp, errno, "cannot duplicate CXLMemSim v2 socket");
    return false;
  }
  return cxl_memsim_v2_client_start_fd(client, fd, cache_capacity, cache_ways,
                                       timeout_ms, errp);
}

bool cxl_memsim_v2_client_transact(CxlMemsimV2Client *client,
                                   CxlMemsimV2Frame *request,
                                   CxlMemsimV2Frame *response, int timeout_ms,
                                   Error **errp) {
  CxlMemsimV2Frame heartbeat;
  CxlMemsimV2Frame heartbeat_response;
  Error *heartbeat_err = NULL;
  uint64_t acknowledge_through = 0;
  int64_t started_ns;
  uint64_t elapsed_ns;
  uint16_t request_type;
  bool success;

  if (!request || request->type == CXL_MEMSIM_V2_OP_REGISTER ||
      request->type == CXL_MEMSIM_V2_OP_RESPONSE ||
      request->type == CXL_MEMSIM_V2_OP_SNOOP_ACK ||
      cxl_memsim_v2_is_snoop(request->type)) {
    error_setg(errp, "invalid CXLMemSim v2 client request opcode");
    return false;
  }
  request_type = request->type;
  started_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
  success = cxl_memsim_v2_transact_internal(client, request, response,
                                            timeout_ms, false, errp);
  elapsed_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - started_ns;
  switch (request_type) {
  case CXL_MEMSIM_V2_OP_GETS:
    qatomic_fetch_add(&client->stats.gets, 1);
    qatomic_fetch_add(&client->stats.gets_ns, elapsed_ns);
    break;
  case CXL_MEMSIM_V2_OP_GETM:
    qatomic_fetch_add(&client->stats.getm, 1);
    qatomic_fetch_add(&client->stats.getm_ns, elapsed_ns);
    break;
  case CXL_MEMSIM_V2_OP_UPGRADE:
    qatomic_fetch_add(&client->stats.upgrade, 1);
    qatomic_fetch_add(&client->stats.upgrade_ns, elapsed_ns);
    break;
  case CXL_MEMSIM_V2_OP_PUTS:
    qatomic_fetch_add(&client->stats.puts, 1);
    qatomic_fetch_add(&client->stats.puts_ns, elapsed_ns);
    break;
  case CXL_MEMSIM_V2_OP_PUTM:
    qatomic_fetch_add(&client->stats.putm, 1);
    qatomic_fetch_add(&client->stats.putm_ns, elapsed_ns);
    break;
  case CXL_MEMSIM_V2_OP_FENCE:
    qatomic_fetch_add(&client->stats.fence, 1);
    qatomic_fetch_add(&client->stats.fence_ns, elapsed_ns);
    break;
  case CXL_MEMSIM_V2_OP_RESIDENT:
    qatomic_fetch_add(&client->stats.resident, 1);
    qatomic_fetch_add(&client->stats.resident_ns, elapsed_ns);
    break;
  default:
    break;
  }
  if (!success || request->type == CXL_MEMSIM_V2_OP_HEARTBEAT) {
    return success;
  }

  qemu_mutex_lock(&client->state_lock);
  client->consumed_response_id =
      MAX(client->consumed_response_id, response->request_id);
  if (!client->response_ack_in_progress &&
      client->consumed_response_id - client->acknowledged_response_id >=
          CXL_MEMSIM_V2_RESPONSE_ACK_INTERVAL) {
    client->response_ack_in_progress = true;
    acknowledge_through = client->consumed_response_id;
  }
  qemu_mutex_unlock(&client->state_lock);
  if (!acknowledge_through) {
    return true;
  }

  cxl_memsim_v2_frame_init(&heartbeat, CXL_MEMSIM_V2_OP_HEARTBEAT);
  heartbeat.old_value = acknowledge_through;
  success =
      cxl_memsim_v2_transact_internal(client, &heartbeat, &heartbeat_response,
                                      timeout_ms, false, &heartbeat_err);
  if (success && heartbeat_response.status != CXL_MEMSIM_V2_STATUS_OK) {
    error_setg(&heartbeat_err, "CXLMemSim v2 heartbeat status %u",
               heartbeat_response.status);
    success = false;
  }
  if (success && (heartbeat_response.state != CXL_MEMSIM_V2_STATE_I ||
                  heartbeat_response.epoch || heartbeat_response.payload_len)) {
    error_setg(&heartbeat_err, "invalid CXLMemSim v2 heartbeat response");
    success = false;
  }

  if (!success) {
    const char *message = heartbeat_err ? error_get_pretty(heartbeat_err)
                                        : "CXLMemSim v2 heartbeat failed";

    cxl_memsim_v2_disconnect(client, message);
  }

  qemu_mutex_lock(&client->state_lock);
  if (success) {
    GHashTableIter iter;
    gpointer key;

    client->acknowledged_response_id =
        MAX(client->acknowledged_response_id, acknowledge_through);
    g_hash_table_iter_init(&iter, client->completed_retries);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
      if (*(uint64_t *)key <= acknowledge_through) {
        g_hash_table_iter_remove(&iter);
      }
    }
  }
  client->response_ack_in_progress = false;
  qemu_mutex_unlock(&client->state_lock);
  error_free(heartbeat_err);
  return true;
}

static bool cxl_memsim_v2_response_ok(const CxlMemsimV2Frame *response,
                                      uint16_t request_opcode, Error **errp) {
  if (response->status == CXL_MEMSIM_V2_STATUS_OK) {
    return true;
  }
  error_setg(errp,
             "CXLMemSim v2 request failed: op=%u request=%" PRIu64
             " addr=0x%" PRIx64 " status=%u response-state=%u"
             " response-epoch=%" PRIu64,
             request_opcode, response->request_id, response->addr,
             response->status, response->state, response->epoch);
  return false;
}

static bool cxl_memsim_v2_acquire_line(
    CxlMemsimV2Client *client, uint64_t line_address, bool modified,
    bool shared_range, uint64_t resident_mask, uint64_t writable_mask,
    CxlMemsimV2Frame *response, int timeout_ms, Error **errp) {
  CxlMemsimV2Frame request;

  cxl_memsim_v2_frame_init(&request, modified ? CXL_MEMSIM_V2_OP_GETM
                                              : CXL_MEMSIM_V2_OP_GETS);
  request.addr = line_address;
  request.state = CXL_MEMSIM_V2_STATE_I;
  request.size = shared_range ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE : 0;
  if (shared_range && resident_mask) {
    request.value = resident_mask;
    request.expected = writable_mask;
  }
  if (!cxl_memsim_v2_client_transact(client, &request, response, timeout_ms,
                                     errp) ||
      !cxl_memsim_v2_response_ok(
          response, modified ? CXL_MEMSIM_V2_OP_GETM : CXL_MEMSIM_V2_OP_GETS,
          errp)) {
    return false;
  }
  if (response->payload_len != (shared_range ? 0 : CXL_MEMSIM_V2_LINE_SIZE) ||
      response->size != request.size || response->value != request.value ||
      response->expected != request.expected ||
      (modified ? response->state != CXL_MEMSIM_V2_STATE_M
                : (response->state != CXL_MEMSIM_V2_STATE_S &&
                   response->state != CXL_MEMSIM_V2_STATE_E)) ||
      !response->epoch) {
    error_setg(errp, "invalid CXLMemSim v2 line grant");
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_release_line(CxlMemsimV2Client *client,
                                       uint64_t line_address,
                                       const CxlMemsimV2Frame *grant,
                                       bool dirty, int timeout_ms,
                                       Error **errp) {
  CxlMemsimV2Frame request;
  CxlMemsimV2Frame response;

  cxl_memsim_v2_frame_init(&request, dirty ? CXL_MEMSIM_V2_OP_PUTM
                                           : CXL_MEMSIM_V2_OP_PUTS);
  request.addr = line_address;
  request.state = grant->state;
  request.epoch = grant->epoch;
  request.size = grant->size;
  if (dirty && grant->size != CXL_MEMSIM_V2_SHARED_RANGE_SIZE) {
    request.payload_len = CXL_MEMSIM_V2_LINE_SIZE;
    memcpy(request.data, grant->data, sizeof(request.data));
  }
  if (!cxl_memsim_v2_client_transact(client, &request, &response, timeout_ms,
                                     errp) ||
      !cxl_memsim_v2_response_ok(
          &response, dirty ? CXL_MEMSIM_V2_OP_PUTM : CXL_MEMSIM_V2_OP_PUTS,
          errp)) {
    return false;
  }
  if (response.state != CXL_MEMSIM_V2_STATE_I ||
      response.epoch <= grant->epoch || response.payload_len ||
      response.size != grant->size) {
    error_setg(errp, "invalid CXLMemSim v2 line release");
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_release_cached_line(CxlMemsimV2Client *client,
                                              const CxlMemsimV2CacheLine *line,
                                              int timeout_ms, Error **errp) {
  CxlMemsimV2Frame grant;

  cxl_memsim_v2_frame_init(&grant, CXL_MEMSIM_V2_OP_RESPONSE);
  grant.state = line->state;
  grant.epoch = line->epoch;
  grant.size = line->shared_range ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE : 0;
  if (!line->shared_range) {
    memcpy(grant.data, line->data, sizeof(grant.data));
  }
  return cxl_memsim_v2_release_line(client, line->address, &grant,
                                    line->state == CXL_MEMSIM_V2_STATE_M,
                                    timeout_ms, errp);
}

static bool cxl_memsim_v2_cache_evict_address(CxlMemsimV2Client *client,
                                              uint64_t line_address,
                                              int timeout_ms, Error **errp) {
  CxlMemsimV2CacheLine snapshot;
  CxlMemsimV2CacheLine *line;

  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, line_address);
  if (!line) {
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }
  snapshot = *line;
  qemu_mutex_unlock(&client->cache_lock);

  if (!cxl_memsim_v2_invalidate_shared_mapping(client, &snapshot,
                                               CXL_MEMSIM_V2_STATE_I, errp)) {
    return false;
  }
  smp_mb();
  if (!cxl_memsim_v2_release_cached_line(client, &snapshot, timeout_ms, errp)) {
    return false;
  }
  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, line_address);
  if (line) {
    memset(line, 0, sizeof(*line));
  }
  qemu_mutex_unlock(&client->cache_lock);
  return true;
}

static void
cxl_memsim_v2_discard_queued_writebacks_locked(CxlMemsimV2Client *client) {
  while (!g_queue_is_empty(&client->writeback_queue)) {
    uint64_t *address = g_queue_pop_head(&client->writeback_queue);

    g_hash_table_remove(client->writeback_pending, address);
  }
}

static void *cxl_memsim_v2_writeback_worker(void *opaque) {
  CxlMemsimV2Client *client = opaque;

  for (;;) {
    uint64_t *address;
    Error *local_err = NULL;
    bool success;

    qemu_mutex_lock(&client->writeback_lock);
    while (g_queue_is_empty(&client->writeback_queue) &&
           !client->writeback_stop) {
      qemu_cond_wait(&client->writeback_available, &client->writeback_lock);
    }
    if (client->writeback_stop && g_queue_is_empty(&client->writeback_queue)) {
      qemu_mutex_unlock(&client->writeback_lock);
      break;
    }
    address = g_queue_pop_head(&client->writeback_queue);
    client->writeback_active++;
    qemu_mutex_unlock(&client->writeback_lock);

    success = cxl_memsim_v2_cache_evict_address(client, *address,
                                                client->timeout_ms, &local_err);

    qemu_mutex_lock(&client->writeback_lock);
    if (!success && !client->writeback_failed) {
      client->writeback_failed = true;
      client->writeback_error =
          g_strdup(local_err ? error_get_pretty(local_err)
                             : "CXLMemSim v2 asynchronous writeback failed");
      cxl_memsim_v2_discard_queued_writebacks_locked(client);
    }
    g_hash_table_remove(client->writeback_pending, address);
    client->writeback_active--;
    if (g_queue_is_empty(&client->writeback_queue) &&
        !client->writeback_active) {
      qemu_cond_broadcast(&client->writeback_drained);
    }
    qemu_mutex_unlock(&client->writeback_lock);
    error_free(local_err);
  }
  return NULL;
}

static void cxl_memsim_v2_start_writeback_workers(CxlMemsimV2Client *client) {
  unsigned index;

  qemu_mutex_lock(&client->writeback_lock);
  client->writeback_thread_count = CXL_MEMSIM_V2_WRITEBACK_WORKERS;
  qemu_mutex_unlock(&client->writeback_lock);
  for (index = 0; index < CXL_MEMSIM_V2_WRITEBACK_WORKERS; index++) {
    qemu_thread_create(&client->writeback_threads[index], "cxl-v2-wb",
                       cxl_memsim_v2_writeback_worker, client,
                       QEMU_THREAD_JOINABLE);
  }
}

static void cxl_memsim_v2_stop_writeback_workers(CxlMemsimV2Client *client) {
  unsigned count;
  unsigned index;

  qemu_mutex_lock(&client->writeback_lock);
  client->writeback_stop = true;
  count = client->writeback_thread_count;
  qemu_cond_broadcast(&client->writeback_available);
  qemu_mutex_unlock(&client->writeback_lock);
  for (index = 0; index < count; index++) {
    qemu_thread_join(&client->writeback_threads[index]);
  }
  qemu_mutex_lock(&client->writeback_lock);
  client->writeback_thread_count = 0;
  qemu_mutex_unlock(&client->writeback_lock);
}

static bool cxl_memsim_v2_queue_writeback(CxlMemsimV2Client *client,
                                          uint64_t line_address, Error **errp) {
  uint64_t *address;

  qemu_mutex_lock(&client->writeback_lock);
  if (!client->writeback_thread_count || client->writeback_stop ||
      client->writeback_failed) {
    error_setg(errp, "%s",
               client->writeback_error
                   ?: "CXLMemSim v2 writeback workers are unavailable");
    qemu_mutex_unlock(&client->writeback_lock);
    return false;
  }
  if (g_hash_table_contains(client->writeback_pending, &line_address)) {
    qemu_mutex_unlock(&client->writeback_lock);
    return true;
  }
  address = g_new(uint64_t, 1);
  *address = line_address;
  g_hash_table_add(client->writeback_pending, address);
  g_queue_push_tail(&client->writeback_queue, address);
  qemu_cond_signal(&client->writeback_available);
  qemu_mutex_unlock(&client->writeback_lock);
  return true;
}

static bool cxl_memsim_v2_drain_writebacks(CxlMemsimV2Client *client,
                                           Error **errp) {
  bool success;

  qemu_mutex_lock(&client->writeback_lock);
  while ((!g_queue_is_empty(&client->writeback_queue) ||
          client->writeback_active) &&
         !client->writeback_failed) {
    qemu_cond_wait(&client->writeback_drained, &client->writeback_lock);
  }
  success = !client->writeback_failed;
  if (!success) {
    error_setg(errp, "%s",
               client->writeback_error
                   ?: "CXLMemSim v2 asynchronous writeback failed");
  }
  qemu_mutex_unlock(&client->writeback_lock);
  return success;
}

static bool cxl_memsim_v2_cache_make_room(CxlMemsimV2Client *client,
                                          uint64_t line_address, int timeout_ms,
                                          Error **errp) {
  uint64_t victim_address;
  CxlMemsimV2CacheLine *victim;

  qemu_mutex_lock(&client->cache_lock);
  victim = cxl_memsim_v2_cache_victim_locked(client, line_address);
  if (!victim) {
    qemu_mutex_unlock(&client->cache_lock);
    error_setg(errp, "CXLMemSim v2 cache set is being invalidated");
    return false;
  }
  if (!victim->valid) {
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }
  victim_address = victim->address;
  qemu_mutex_unlock(&client->cache_lock);
  return cxl_memsim_v2_cache_evict_address(client, victim_address, timeout_ms,
                                           errp);
}

static bool cxl_memsim_v2_upgrade_line(CxlMemsimV2Client *client,
                                       const CxlMemsimV2CacheLine *line,
                                       uint64_t resident_mask,
                                       uint64_t writable_mask,
                                       CxlMemsimV2Frame *response,
                                       int timeout_ms, Error **errp) {
  CxlMemsimV2Frame request;

  cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_UPGRADE);
  request.addr = line->address;
  request.state = line->state;
  request.epoch = line->epoch;
  request.size = line->shared_range ? CXL_MEMSIM_V2_SHARED_RANGE_SIZE : 0;
  if (line->shared_range && resident_mask) {
    request.value = resident_mask;
    request.expected = writable_mask;
  }
  if (!cxl_memsim_v2_client_transact(client, &request, response, timeout_ms,
                                     errp)) {
    return false;
  }
  if (!cxl_memsim_v2_response_ok(response, CXL_MEMSIM_V2_OP_UPGRADE, errp)) {
    error_prepend(errp,
                  "CXLMemSim v2 upgrade state=%u epoch=%" PRIu64
                  " resident=0x%" PRIx64 " writable=0x%" PRIx64 ": ",
                  request.state, request.epoch, resident_mask, writable_mask);
    return false;
  }
  if (response->state != CXL_MEMSIM_V2_STATE_M ||
      response->epoch <= line->epoch || response->payload_len ||
      response->size != request.size || response->value != request.value ||
      response->expected != request.expected) {
    error_setg(errp, "invalid CXLMemSim v2 upgrade grant");
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_extend_modified_shared_residency(
    CxlMemsimV2Client *client, const CxlMemsimV2CacheLine *line,
    uint64_t resident_mask, uint64_t writable_mask, CxlMemsimV2Frame *response,
    int timeout_ms, Error **errp) {
  CxlMemsimV2Frame request;

  cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_GETM);
  request.addr = line->address;
  request.state = CXL_MEMSIM_V2_STATE_M;
  request.epoch = line->epoch;
  request.value = resident_mask;
  request.expected = writable_mask;
  request.size = CXL_MEMSIM_V2_SHARED_RANGE_SIZE;
  if (!cxl_memsim_v2_client_transact(client, &request, response, timeout_ms,
                                     errp) ||
      !cxl_memsim_v2_response_ok(response, CXL_MEMSIM_V2_OP_GETM, errp)) {
    return false;
  }
  if (response->state != CXL_MEMSIM_V2_STATE_M ||
      response->epoch <= line->epoch || response->payload_len ||
      response->size != request.size || response->value != request.value ||
      response->expected != request.expected) {
    error_setg(errp, "invalid CXLMemSim v2 modified residency extension");
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_extend_shared_residency(
    CxlMemsimV2Client *client, const CxlMemsimV2CacheLine *line,
    uint64_t resident_mask, CxlMemsimV2Frame *response, int timeout_ms,
    Error **errp) {
  CxlMemsimV2Frame request;

  cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_RESIDENT);
  request.addr = line->address;
  request.state = line->state;
  request.epoch = line->epoch;
  request.value = resident_mask;
  request.size = CXL_MEMSIM_V2_SHARED_RANGE_SIZE;
  if (!cxl_memsim_v2_client_transact(client, &request, response, timeout_ms,
                                     errp) ||
      !cxl_memsim_v2_response_ok(response, CXL_MEMSIM_V2_OP_RESIDENT, errp)) {
    return false;
  }
  if (response->state != request.state || response->epoch != request.epoch ||
      response->payload_len || response->size != request.size ||
      response->value != request.value || response->expected) {
    error_setg(errp, "invalid CXLMemSim v2 residency extension");
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_release_shared_residency(
    CxlMemsimV2Client *client, const CxlMemsimV2CacheLine *line,
    uint64_t resident_mask, CxlMemsimV2Frame *response, int timeout_ms,
    Error **errp) {
  CxlMemsimV2Frame request;

  cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_RESIDENT);
  request.addr = line->address;
  request.state = line->state;
  request.epoch = line->epoch;
  request.expected = resident_mask;
  request.size = CXL_MEMSIM_V2_SHARED_RANGE_SIZE;
  if (!cxl_memsim_v2_client_transact(client, &request, response, timeout_ms,
                                     errp) ||
      !cxl_memsim_v2_response_ok(response, CXL_MEMSIM_V2_OP_RESIDENT, errp)) {
    return false;
  }
  if (response->state != request.state || response->epoch != request.epoch ||
      response->payload_len || response->size != request.size ||
      response->value || response->expected != request.expected) {
    error_setg(errp, "invalid CXLMemSim v2 residency release");
    return false;
  }
  return true;
}

static bool
cxl_memsim_v2_cache_snapshot_changed(CxlMemsimV2Client *client,
                                     uint64_t line_address,
                                     const CxlMemsimV2CacheLine *snapshot) {
  CxlMemsimV2CacheLine *line;
  bool changed;

  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, line_address);
  changed = !line || line->state != snapshot->state ||
            line->epoch != snapshot->epoch ||
            line->shared_range != snapshot->shared_range ||
            line->shared_mapping != snapshot->shared_mapping ||
            line->resident_mask != snapshot->resident_mask ||
            line->writable_mask != snapshot->writable_mask;
  qemu_mutex_unlock(&client->cache_lock);
  return changed;
}

static bool cxl_memsim_v2_permission_race(CxlMemsimV2Client *client,
                                          uint64_t line_address,
                                          const CxlMemsimV2CacheLine *snapshot,
                                          const CxlMemsimV2Frame *response) {
  return (response->status == CXL_MEMSIM_V2_STATUS_INVALID_STATE ||
          response->status == CXL_MEMSIM_V2_STATUS_STALE_EPOCH) &&
         cxl_memsim_v2_cache_snapshot_changed(client, line_address, snapshot);
}

static size_t cxl_memsim_v2_cache_set_resident_pages_locked(
    CxlMemsimV2Client *client, size_t set) {
  const size_t first = set * client->cache_ways;
  size_t pages = 0;
  size_t way;

  for (way = 0; way < client->cache_ways; ++way) {
    const CxlMemsimV2CacheLine *line = &client->cache[first + way];

    if (line->valid && line->shared_range) {
      pages += __builtin_popcountll(line->resident_mask);
    }
  }
  return pages;
}

static CxlMemsimV2CacheLine *
cxl_memsim_v2_cache_residency_victim_locked(CxlMemsimV2Client *client,
                                             size_t set,
                                             uint64_t excluded_address) {
  const size_t first = set * client->cache_ways;
  CxlMemsimV2CacheLine *clean = NULL;
  CxlMemsimV2CacheLine *modified = NULL;
  size_t way;

  for (way = 0; way < client->cache_ways; ++way) {
    CxlMemsimV2CacheLine *candidate = &client->cache[first + way];

    if (!candidate->valid || candidate->invalidating ||
        !candidate->shared_range || !candidate->resident_mask ||
        candidate->address == excluded_address) {
      continue;
    }
    if (candidate->state == CXL_MEMSIM_V2_STATE_M) {
      if (!modified || candidate->last_used < modified->last_used) {
        modified = candidate;
      }
    } else if (!clean || candidate->last_used < clean->last_used) {
      clean = candidate;
    }
  }
  return clean ?: modified;
}

static bool cxl_memsim_v2_cache_drop_clean_residency(
    CxlMemsimV2Client *client, uint64_t line_address, int timeout_ms,
    Error **errp) {
  CxlMemsimV2CacheLine snapshot;
  CxlMemsimV2CacheLine *line;
  CxlMemsimV2Frame response = {0};
  uint64_t released_mask;

  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, line_address);
  if (!line || !line->shared_range || !line->resident_mask ||
      line->state == CXL_MEMSIM_V2_STATE_M) {
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }
  snapshot = *line;
  qemu_mutex_unlock(&client->cache_lock);

  if (!cxl_memsim_v2_invalidate_shared_mapping(client, &snapshot,
                                               CXL_MEMSIM_V2_STATE_I, errp)) {
    return false;
  }
  smp_mb();
  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, line_address);
  if (!line || line->state != snapshot.state || line->epoch != snapshot.epoch ||
      line->resident_mask != snapshot.resident_mask ||
      line->shared_mapping != snapshot.shared_mapping) {
    qemu_mutex_unlock(&client->cache_lock);
    return true;
  }
  released_mask = line->resident_mask;
  line->resident_mask = 0;
  line->shared_mapping = NULL;
  qemu_mutex_unlock(&client->cache_lock);

  if (!cxl_memsim_v2_release_shared_residency(
          client, &snapshot, released_mask, &response, timeout_ms, errp)) {
    bool raced = false;

    if (response.status == CXL_MEMSIM_V2_STATUS_INVALID_STATE ||
        response.status == CXL_MEMSIM_V2_STATUS_STALE_EPOCH) {
      qemu_mutex_lock(&client->cache_lock);
      line = cxl_memsim_v2_cache_find_locked(client, line_address);
      raced = !line || line->state != snapshot.state ||
              line->epoch != snapshot.epoch;
      qemu_mutex_unlock(&client->cache_lock);
    }
    if (raced) {
      if (errp && *errp) {
        error_free(*errp);
        *errp = NULL;
      }
      return true;
    }
    return false;
  }
  return true;
}

static bool cxl_memsim_v2_cache_make_resident_room(
    CxlMemsimV2Client *client, uint64_t line_address,
    size_t additional_pages, int timeout_ms, Error **errp) {
  const size_t set = cxl_memsim_v2_cache_set(client, line_address);

  if (!additional_pages || !client->cache_resident_pages_per_set) {
    return true;
  }
  if (additional_pages > client->cache_resident_pages_per_set) {
    error_setg(errp, "CXLMemSim v2 residency request exceeds cache set");
    return false;
  }
  for (;;) {
    CxlMemsimV2CacheLine *victim;
    uint64_t victim_address;
    bool modified;
    size_t resident_pages;

    qemu_mutex_lock(&client->cache_lock);
    resident_pages =
        cxl_memsim_v2_cache_set_resident_pages_locked(client, set);
    if (resident_pages + additional_pages <=
        client->cache_resident_pages_per_set) {
      qemu_mutex_unlock(&client->cache_lock);
      return true;
    }
    victim = cxl_memsim_v2_cache_residency_victim_locked(
        client, set, line_address);
    if (!victim) {
      qemu_mutex_unlock(&client->cache_lock);
      error_setg(errp, "CXLMemSim v2 cache set has no residency victim");
      return false;
    }
    victim_address = victim->address;
    modified = victim->state == CXL_MEMSIM_V2_STATE_M;
    qemu_mutex_unlock(&client->cache_lock);

    if (modified) {
      if (!cxl_memsim_v2_cache_evict_address(client, victim_address,
                                             timeout_ms, errp)) {
        return false;
      }
    } else if (!cxl_memsim_v2_cache_drop_clean_residency(
                   client, victim_address, timeout_ms, errp)) {
      return false;
    }
  }
}

static bool cxl_memsim_v2_cache_ensure(CxlMemsimV2Client *client,
                                       uint64_t line_address, bool modified,
                                       bool shared_range, void *shared_mapping,
                                       uint64_t resident_mask,
                                       uint64_t writable_mask, int timeout_ms,
                                       Error **errp) {
  const uint64_t effective_resident_mask =
      shared_range && !resident_mask ? CXL_MEMSIM_V2_RESIDENCY_FULL_MASK
                                     : resident_mask;

  for (;;) {
    CxlMemsimV2CacheLine snapshot;
    CxlMemsimV2CacheLine *line;
    CxlMemsimV2Frame grant = {0};

    if (shared_range && !cxl_memsim_v2_bind_shared_mapping(
                            client, line_address, shared_mapping, errp)) {
      return false;
    }

    qemu_mutex_lock(&client->cache_lock);
    line = cxl_memsim_v2_cache_find_locked(client, line_address);
    if (line && line->shared_range == shared_range &&
        (!shared_range ||
         ((line->resident_mask & effective_resident_mask) ==
              effective_resident_mask &&
          (line->writable_mask & writable_mask) == writable_mask)) &&
        (!modified || line->state == CXL_MEMSIM_V2_STATE_M)) {
      cxl_memsim_v2_cache_touch_locked(client, line);
      qemu_mutex_unlock(&client->cache_lock);
      return true;
    }
    if (line) {
      snapshot = *line;
      qemu_mutex_unlock(&client->cache_lock);
      if (shared_range && modified && snapshot.state == CXL_MEMSIM_V2_STATE_M) {
        const uint64_t missing =
            effective_resident_mask & ~snapshot.resident_mask;
        Error *request_err = NULL;

        if (!cxl_memsim_v2_cache_make_resident_room(
                client, line_address, __builtin_popcountll(missing),
                timeout_ms, &request_err)) {
          error_propagate(errp, request_err);
          return false;
        }
        if (!cxl_memsim_v2_extend_modified_shared_residency(
                client, &snapshot, resident_mask, writable_mask, &grant,
                timeout_ms, &request_err)) {
          if (cxl_memsim_v2_permission_race(client, line_address, &snapshot,
                                            &grant)) {
            error_free(request_err);
            continue;
          }
          error_propagate(errp, request_err);
          return false;
        }
        continue;
      }
      if (shared_range && !modified &&
          (snapshot.resident_mask & effective_resident_mask) !=
              effective_resident_mask) {
        const uint64_t missing =
            effective_resident_mask & ~snapshot.resident_mask;
        Error *request_err = NULL;

        if (!cxl_memsim_v2_cache_make_resident_room(
                client, line_address, __builtin_popcountll(missing),
                timeout_ms, &request_err)) {
          error_propagate(errp, request_err);
          return false;
        }
        if (!cxl_memsim_v2_extend_shared_residency(
                client, &snapshot, missing, &grant, timeout_ms, &request_err)) {
          if (cxl_memsim_v2_permission_race(client, line_address, &snapshot,
                                            &grant)) {
            error_free(request_err);
            continue;
          }
          error_propagate(errp, request_err);
          return false;
        }
        qemu_mutex_lock(&client->cache_lock);
        line = cxl_memsim_v2_cache_find_locked(client, line_address);
        if (!line || line->state != snapshot.state ||
            line->epoch != snapshot.epoch) {
          qemu_mutex_unlock(&client->cache_lock);
          continue;
        }
        if (!line->shared_range ||
            line->shared_mapping != snapshot.shared_mapping) {
          qemu_mutex_unlock(&client->cache_lock);
          error_setg(errp, "CXLMemSim v2 residency mapping changed");
          return false;
        }
        line->resident_mask |= missing;
        cxl_memsim_v2_cache_touch_locked(client, line);
        qemu_mutex_unlock(&client->cache_lock);
        continue;
      }
      Error *request_err = NULL;
      bool granted;
      const uint64_t missing =
          shared_range ? effective_resident_mask & ~snapshot.resident_mask : 0;

      if (!cxl_memsim_v2_cache_make_resident_room(
              client, line_address, __builtin_popcountll(missing), timeout_ms,
              &request_err)) {
        error_propagate(errp, request_err);
        return false;
      }
      granted = cxl_memsim_v2_upgrade_line(client, &snapshot, resident_mask,
                                           writable_mask, &grant, timeout_ms,
                                           &request_err);
      if (!granted) {
        if (cxl_memsim_v2_permission_race(client, line_address, &snapshot,
                                          &grant)) {
          error_free(request_err);
          continue;
        }
        error_propagate(errp, request_err);
        return false;
      }
      continue;
    }
    qemu_mutex_unlock(&client->cache_lock);

    if (!cxl_memsim_v2_cache_make_room(client, line_address, timeout_ms,
                                       errp) ||
        !cxl_memsim_v2_cache_make_resident_room(
            client, line_address,
            __builtin_popcountll(effective_resident_mask), timeout_ms,
            errp) ||
        !cxl_memsim_v2_acquire_line(client, line_address, modified,
                                    shared_range, resident_mask, writable_mask,
                                    &grant, timeout_ms, errp)) {
      return false;
    }
  }
}

static bool cxl_memsim_v2_access_size_valid(uint64_t address, unsigned size) {
  return (size == 1 || size == 2 || size == 4 || size == 8) &&
         address <= UINT64_MAX - size;
}

static bool cxl_memsim_v2_bind_shared_mapping(CxlMemsimV2Client *client,
                                              uint64_t page_address,
                                              void *mapping, Error **errp) {
  void *current;
  CxlMemsimV2CacheLine *line;
  uint64_t *key;

  if (!mapping) {
    error_setg(errp, "missing CXLMemSim v2 shared mapping");
    return false;
  }
  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, page_address);
  if (line) {
    bool matches = line->shared_range && line->shared_mapping == mapping;

    if (line->shared_range && line->resident_mask == 0 &&
        !line->shared_mapping) {
      line->shared_mapping = mapping;
      matches = true;
    }

    qemu_mutex_unlock(&client->cache_lock);
    if (!matches) {
      error_setg(errp, "conflicting CXLMemSim v2 cached mapping");
    }
    return matches;
  }
  current = g_hash_table_lookup(client->shared_mappings, &page_address);
  if (current && current != mapping) {
    qemu_mutex_unlock(&client->cache_lock);
    error_setg(errp, "conflicting CXLMemSim v2 shared mapping");
    return false;
  }
  if (!current) {
    key = g_new(uint64_t, 1);
    *key = page_address;
    g_hash_table_insert(client->shared_mappings, key, mapping);
  }
  qemu_mutex_unlock(&client->cache_lock);
  return true;
}

static void cxl_memsim_v2_unbind_shared_mapping(CxlMemsimV2Client *client,
                                                uint64_t page_address,
                                                void *mapping) {
  qemu_mutex_lock(&client->cache_lock);
  {
    CxlMemsimV2CacheLine *line =
        cxl_memsim_v2_cache_find_locked(client, page_address);

    if (line && line->shared_range && line->resident_mask == 0 &&
        line->shared_mapping == mapping) {
      line->shared_mapping = NULL;
    }
  }
  if (g_hash_table_lookup(client->shared_mappings, &page_address) == mapping) {
    g_hash_table_remove(client->shared_mappings, &page_address);
  }
  qemu_mutex_unlock(&client->cache_lock);
}

static bool cxl_memsim_v2_shared_access(CxlMemsimV2Client *client,
                                        uint64_t address, unsigned size,
                                        uint64_t *value, void *mapping,
                                        bool write, bool exclusive,
                                        int timeout_ms, Error **errp) {
  CxlMemsimV2OperationGuard guard;
  uint8_t bytes[sizeof(*value)] = {0};
  uint64_t cursor = address;
  unsigned copied = 0;
  bool success = false;

  if (!client || !value || !client->shared_access_handler ||
      !(client->capabilities & CXL_MEMSIM_V2_CAP_SHARED_RANGE) ||
      !cxl_memsim_v2_access_size_valid(address, size)) {
    error_setg(errp, "invalid CXLMemSim v2 shared-range access");
    return false;
  }
  if (write) {
    stn_le_p(bytes, size, *value);
  }
  cxl_memsim_v2_operation_begin(client, address, size, &guard);
  while (copied < size) {
    CxlMemsimV2CacheLine *line;
    uint64_t page_address =
        cursor & ~(uint64_t)(CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1);
    unsigned page_offset = cursor & (CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1);
    unsigned chunk =
        MIN(size - copied, CXL_MEMSIM_V2_SHARED_RANGE_SIZE - page_offset);

    if (!cxl_memsim_v2_cache_ensure(client, page_address, write || exclusive,
                                    true, mapping, 0, 0, timeout_ms, errp)) {
      cxl_memsim_v2_unbind_shared_mapping(client, page_address, mapping);
      goto out;
    }
    qemu_mutex_lock(&client->state_lock);
    if (!client->connected) {
      error_setg(errp, "%s",
                 client->connection_error
                     ?: "CXLMemSim v2 client is disconnected");
      qemu_mutex_unlock(&client->state_lock);
      goto out;
    }
    qemu_mutex_lock(&client->cache_lock);
    line = cxl_memsim_v2_cache_find_locked(client, page_address);
    if (!line || !line->shared_range || line->shared_mapping != mapping ||
        ((write || exclusive) && line->state != CXL_MEMSIM_V2_STATE_M)) {
      qemu_mutex_unlock(&client->cache_lock);
      qemu_mutex_unlock(&client->state_lock);
      error_setg(errp, "CXLMemSim v2 shared-range grant was invalidated");
      goto out;
    }
    if (!client->shared_access_handler(client->shared_access_opaque, mapping,
                                       cursor, bytes + copied, chunk, write,
                                       errp)) {
      qemu_mutex_unlock(&client->cache_lock);
      qemu_mutex_unlock(&client->state_lock);
      goto out;
    }
    if (write) {
      line->dirty = true;
      smp_wmb();
    }
    cxl_memsim_v2_cache_touch_locked(client, line);
    qemu_mutex_unlock(&client->cache_lock);
    qemu_mutex_unlock(&client->state_lock);
    cursor += chunk;
    copied += chunk;
  }
  if (!write) {
    *value = ldn_le_p(bytes, size);
  }
  success = true;

out:
  cxl_memsim_v2_operation_end(client, &guard);
  return success;
}

bool cxl_memsim_v2_shared_load(CxlMemsimV2Client *client, uint64_t address,
                               unsigned size, uint64_t *value, void *mapping,
                               int timeout_ms, Error **errp) {
  return cxl_memsim_v2_shared_access(client, address, size, value, mapping,
                                     false, false, timeout_ms, errp);
}

bool cxl_memsim_v2_shared_load_exclusive(CxlMemsimV2Client *client,
                                         uint64_t address, unsigned size,
                                         uint64_t *value, void *mapping,
                                         int timeout_ms, Error **errp) {
  return cxl_memsim_v2_shared_access(client, address, size, value, mapping,
                                     false, true, timeout_ms, errp);
}

bool cxl_memsim_v2_shared_store(CxlMemsimV2Client *client, uint64_t address,
                                unsigned size, uint64_t value, void *mapping,
                                int timeout_ms, Error **errp) {
  return cxl_memsim_v2_shared_access(client, address, size, &value, mapping,
                                     true, true, timeout_ms, errp);
}

static uint64_t cxl_memsim_v2_direct_demand_mask(CxlMemsimV2Client *client,
                                                 uint64_t address, bool write) {
  const uint64_t page =
      address & ~(uint64_t)(CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE - 1);
  const unsigned subpage = (page & (CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1)) /
                           CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE;
  const unsigned stream = write ? 1 : 0;
  bool sequential;
  uint64_t mask = UINT64_C(1) << subpage;

  qemu_mutex_lock(&client->cache_lock);
  sequential = client->last_direct_page_valid[stream] &&
               client->last_direct_page[stream] <=
                   UINT64_MAX - CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE &&
               page == client->last_direct_page[stream] +
                           CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE;
  client->last_direct_page[stream] = page;
  client->last_direct_page_valid[stream] = true;
  qemu_mutex_unlock(&client->cache_lock);
  if (sequential) {
    mask = CXL_MEMSIM_V2_RESIDENCY_FULL_MASK &
           (CXL_MEMSIM_V2_RESIDENCY_FULL_MASK << subpage);
  }
  return mask;
}

bool cxl_memsim_v2_shared_grant(CxlMemsimV2Client *client, uint64_t address,
                                void *mapping, bool write,
                                CxlMemsimV2LineState *state, int timeout_ms,
                                Error **errp) {
  CxlMemsimV2OperationGuard guard;
  CxlMemsimV2CacheLine *line;
  uint64_t page_address =
      address & ~(uint64_t)(CXL_MEMSIM_V2_SHARED_RANGE_SIZE - 1);
  uint64_t demand_mask;
  uint64_t resident_mask;
  uint64_t writable_mask;
  bool success = false;

  if (!client || !mapping || !state ||
      !(client->capabilities & CXL_MEMSIM_V2_CAP_SHARED_RANGE)) {
    error_setg(errp, "invalid CXLMemSim v2 direct shared-range grant");
    return false;
  }
  demand_mask = cxl_memsim_v2_direct_demand_mask(client, address, write);
  resident_mask = demand_mask | (write ? UINT64_C(1) : 0);
  writable_mask = write ? demand_mask : 0;
  cxl_memsim_v2_operation_begin(client, page_address,
                                CXL_MEMSIM_V2_SHARED_RANGE_SIZE, &guard);
  if (!cxl_memsim_v2_cache_ensure(client, page_address, write, true, mapping,
                                  resident_mask, writable_mask, timeout_ms,
                                  errp)) {
    cxl_memsim_v2_unbind_shared_mapping(client, page_address, mapping);
    goto out;
  }
  qemu_mutex_lock(&client->state_lock);
  if (!client->connected) {
    error_setg(errp, "%s",
               client->connection_error
                   ?: "CXLMemSim v2 client is disconnected");
    qemu_mutex_unlock(&client->state_lock);
    goto out;
  }
  qemu_mutex_lock(&client->cache_lock);
  line = cxl_memsim_v2_cache_find_locked(client, page_address);
  if (!line || !line->shared_range || line->shared_mapping != mapping ||
      (line->resident_mask & resident_mask) != resident_mask ||
      (line->writable_mask & writable_mask) != writable_mask ||
      (write && line->state != CXL_MEMSIM_V2_STATE_M)) {
    qemu_mutex_unlock(&client->cache_lock);
    qemu_mutex_unlock(&client->state_lock);
    error_setg(errp, "CXLMemSim v2 direct grant was invalidated");
    goto out;
  }
  if (write) {
    /* Conservative: a writable TCG mapping may dirty the page at any time. */
    line->dirty = true;
    smp_wmb();
  }
  *state = line->state;
  cxl_memsim_v2_cache_touch_locked(client, line);
  qemu_mutex_unlock(&client->cache_lock);
  qemu_mutex_unlock(&client->state_lock);
  success = true;

out:
  cxl_memsim_v2_operation_end(client, &guard);
  return success;
}

static bool cxl_memsim_v2_load_policy(CxlMemsimV2Client *client,
                                      uint64_t address, unsigned size,
                                      uint64_t *value, int timeout_ms,
                                      bool exclusive, Error **errp) {
  CxlMemsimV2OperationGuard guard;
  uint8_t bytes[sizeof(*value)] = {0};
  uint64_t cursor = address;
  unsigned copied = 0;
  bool success = false;

  if (!client || !value || !cxl_memsim_v2_access_size_valid(address, size)) {
    error_setg(errp, "invalid CXLMemSim v2 load");
    return false;
  }
  if (cxl_memsim_v2_shared_ranges_enabled(client)) {
    error_setg(errp, "line load is unavailable in shared-range mode");
    return false;
  }
  cxl_memsim_v2_operation_begin(client, address, size, &guard);
  if (!cxl_memsim_v2_drain_writebacks(client, errp)) {
    goto out;
  }
  while (copied < size) {
    CxlMemsimV2CacheLine *line;
    uint64_t line_address = cursor & ~(uint64_t)(CXL_MEMSIM_V2_LINE_SIZE - 1);
    unsigned line_offset = cursor & (CXL_MEMSIM_V2_LINE_SIZE - 1);
    unsigned chunk = MIN(size - copied, CXL_MEMSIM_V2_LINE_SIZE - line_offset);

    if (!cxl_memsim_v2_cache_ensure(client, line_address, exclusive, false,
                                    NULL, 0, 0, timeout_ms, errp)) {
      goto out;
    }
    qemu_mutex_lock(&client->state_lock);
    if (!client->connected) {
      error_setg(errp, "%s",
                 client->connection_error
                     ?: "CXLMemSim v2 client is disconnected");
      qemu_mutex_unlock(&client->state_lock);
      goto out;
    }
    qemu_mutex_lock(&client->cache_lock);
    line = cxl_memsim_v2_cache_find_locked(client, line_address);
    if (!line) {
      qemu_mutex_unlock(&client->cache_lock);
      qemu_mutex_unlock(&client->state_lock);
      error_setg(errp, "CXLMemSim v2 load grant was invalidated");
      goto out;
    }
    memcpy(bytes + copied, line->data + line_offset, chunk);
    cxl_memsim_v2_cache_touch_locked(client, line);
    qemu_mutex_unlock(&client->cache_lock);
    qemu_mutex_unlock(&client->state_lock);
    cursor += chunk;
    copied += chunk;
  }
  *value = ldn_le_p(bytes, size);
  success = true;

out:
  cxl_memsim_v2_operation_end(client, &guard);
  return success;
}

bool cxl_memsim_v2_load(CxlMemsimV2Client *client, uint64_t address,
                        unsigned size, uint64_t *value, int timeout_ms,
                        Error **errp) {
  return cxl_memsim_v2_load_policy(client, address, size, value, timeout_ms,
                                   false, errp);
}

bool cxl_memsim_v2_load_exclusive(CxlMemsimV2Client *client, uint64_t address,
                                  unsigned size, uint64_t *value,
                                  int timeout_ms, Error **errp) {
  return cxl_memsim_v2_load_policy(client, address, size, value, timeout_ms,
                                   true, errp);
}

bool cxl_memsim_v2_store(CxlMemsimV2Client *client, uint64_t address,
                         unsigned size, uint64_t value, int timeout_ms,
                         Error **errp) {
  CxlMemsimV2OperationGuard guard;
  uint8_t bytes[sizeof(value)] = {0};
  uint64_t cursor = address;
  unsigned copied = 0;
  bool success = false;

  if (!client || !cxl_memsim_v2_access_size_valid(address, size)) {
    error_setg(errp, "invalid CXLMemSim v2 store");
    return false;
  }
  if (cxl_memsim_v2_shared_ranges_enabled(client)) {
    error_setg(errp, "line store is unavailable in shared-range mode");
    return false;
  }
  stn_le_p(bytes, size, value);
  cxl_memsim_v2_operation_begin(client, address, size, &guard);
  if (!cxl_memsim_v2_drain_writebacks(client, errp)) {
    goto out;
  }
  while (copied < size) {
    CxlMemsimV2CacheLine *line;
    uint64_t line_address = cursor & ~(uint64_t)(CXL_MEMSIM_V2_LINE_SIZE - 1);
    unsigned line_offset = cursor & (CXL_MEMSIM_V2_LINE_SIZE - 1);
    unsigned chunk = MIN(size - copied, CXL_MEMSIM_V2_LINE_SIZE - line_offset);

    if (!cxl_memsim_v2_cache_ensure(client, line_address, true, false, NULL, 0,
                                    0, timeout_ms, errp)) {
      goto out;
    }
    qemu_mutex_lock(&client->state_lock);
    if (!client->connected) {
      error_setg(errp, "%s",
                 client->connection_error
                     ?: "CXLMemSim v2 client is disconnected");
      qemu_mutex_unlock(&client->state_lock);
      goto out;
    }
    qemu_mutex_lock(&client->cache_lock);
    line = cxl_memsim_v2_cache_find_locked(client, line_address);
    if (!line || line->state != CXL_MEMSIM_V2_STATE_M) {
      qemu_mutex_unlock(&client->cache_lock);
      qemu_mutex_unlock(&client->state_lock);
      error_setg(errp, "CXLMemSim v2 store grant was invalidated");
      goto out;
    }
    memcpy(line->data + line_offset, bytes + copied, chunk);
    line->dirty = true;
    cxl_memsim_v2_cache_touch_locked(client, line);
    qemu_mutex_unlock(&client->cache_lock);
    qemu_mutex_unlock(&client->state_lock);
    if (client->write_policy == CXL_MEMSIM_V2_WRITE_THROUGH &&
        !cxl_memsim_v2_cache_evict_address(client, line_address, timeout_ms,
                                           errp)) {
      goto out;
    }
    cursor += chunk;
    copied += chunk;
  }
  success = true;

out:
  cxl_memsim_v2_operation_end(client, &guard);
  return success;
}

static bool cxl_memsim_v2_atomic(CxlMemsimV2Client *client,
                                 CxlMemsimV2Opcode opcode, uint64_t address,
                                 uint64_t expected, uint64_t operand,
                                 uint64_t *old_value, uint64_t *new_value,
                                 int timeout_ms, Error **errp) {
  CxlMemsimV2OperationGuard guard;
  CxlMemsimV2Frame request;
  CxlMemsimV2Frame response;
  Error *release_err = NULL;
  uint64_t line_address;
  unsigned line_offset;
  bool success = false;

  if (!client || !old_value || !new_value || address % 8 ||
      (address & (CXL_MEMSIM_V2_LINE_SIZE - 1)) >
          CXL_MEMSIM_V2_LINE_SIZE - sizeof(uint64_t)) {
    error_setg(errp, "invalid CXLMemSim v2 atomic address");
    return false;
  }
  if (cxl_memsim_v2_shared_ranges_enabled(client)) {
    error_setg(errp, "line atomic is unavailable in shared-range mode");
    return false;
  }
  cxl_memsim_v2_operation_begin(client, address, sizeof(uint64_t), &guard);
  if (!cxl_memsim_v2_drain_writebacks(client, errp)) {
    goto out;
  }
  line_address = address & ~(uint64_t)(CXL_MEMSIM_V2_LINE_SIZE - 1);
  if (!cxl_memsim_v2_cache_evict_address(client, line_address, timeout_ms,
                                         errp) ||
      !cxl_memsim_v2_cache_make_room(client, line_address, timeout_ms, errp)) {
    goto out;
  }
  cxl_memsim_v2_frame_init(&request, opcode);
  request.addr = address;
  request.state = CXL_MEMSIM_V2_STATE_I;
  request.expected = expected;
  request.value = operand;
  request.size = sizeof(uint64_t);
  if (!cxl_memsim_v2_client_transact(client, &request, &response, timeout_ms,
                                     errp) ||
      !cxl_memsim_v2_response_ok(&response, opcode, errp)) {
    goto out;
  }
  if (response.state != CXL_MEMSIM_V2_STATE_M ||
      response.payload_len != CXL_MEMSIM_V2_LINE_SIZE || !response.epoch) {
    error_setg(errp, "invalid CXLMemSim v2 atomic grant");
    goto out;
  }
  line_offset = address & (CXL_MEMSIM_V2_LINE_SIZE - 1);
  *old_value = response.old_value;
  *new_value = ldq_le_p(response.data + line_offset);
  if (!cxl_memsim_v2_cache_evict_address(client, line_address, timeout_ms,
                                         &release_err)) {
    const char *message = release_err
                              ? error_get_pretty(release_err)
                              : "CXLMemSim v2 atomic grant release failed";
    CxlMemsimV2CacheLine *line;

    cxl_memsim_v2_disconnect(client, message);
    qemu_mutex_lock(&client->cache_lock);
    line = cxl_memsim_v2_cache_find_locked(client, line_address);
    if (line) {
      memset(line, 0, sizeof(*line));
    }
    qemu_mutex_unlock(&client->cache_lock);
    error_free(release_err);
  }
  success = true;

out:
  cxl_memsim_v2_operation_end(client, &guard);
  return success;
}

bool cxl_memsim_v2_fetch_add(CxlMemsimV2Client *client, uint64_t address,
                             uint64_t addend, uint64_t *old_value,
                             uint64_t *new_value, int timeout_ms,
                             Error **errp) {
  return cxl_memsim_v2_atomic(client, CXL_MEMSIM_V2_OP_ATOMIC_FAA, address, 0,
                              addend, old_value, new_value, timeout_ms, errp);
}

bool cxl_memsim_v2_compare_exchange(CxlMemsimV2Client *client, uint64_t address,
                                    uint64_t expected, uint64_t desired,
                                    uint64_t *old_value, uint64_t *new_value,
                                    int timeout_ms, Error **errp) {
  return cxl_memsim_v2_atomic(client, CXL_MEMSIM_V2_OP_ATOMIC_CAS, address,
                              expected, desired, old_value, new_value,
                              timeout_ms, errp);
}

bool cxl_memsim_v2_fence(CxlMemsimV2Client *client, int timeout_ms,
                         Error **errp) {
  CxlMemsimV2Frame request;
  CxlMemsimV2Frame response;
  GArray *release_addresses;
  GArray *shared_lines;
  bool shared_ranges;
  bool success = false;
  size_t index;

  if (!client) {
    error_setg(errp, "invalid CXLMemSim v2 fence client");
    return false;
  }
  release_addresses = g_array_new(false, false, sizeof(uint64_t));
  shared_lines = g_array_new(false, false, sizeof(CxlMemsimV2CacheLine));
  g_rw_lock_writer_lock(&client->operation_barrier);
  shared_ranges = cxl_memsim_v2_shared_ranges_enabled(client);
  if (!cxl_memsim_v2_drain_writebacks(client, errp)) {
    goto out;
  }
  /* End every shared direct-map lifetime before persistence. The server
   * flushes the endpoint's dirty pages and releases the corresponding MESI
   * holders in one FENCE; a later access acquires a fresh grant. Inline cache
   * lines still require ordinary PUTM writeback. */
  qemu_mutex_lock(&client->cache_lock);
  for (index = 0; index < client->cache_line_count; index++) {
    if (client->cache[index].valid) {
      if (client->cache[index].shared_range) {
        CxlMemsimV2CacheLine snapshot = client->cache[index];

        g_array_append_val(shared_lines, snapshot);
      } else if (client->cache[index].state == CXL_MEMSIM_V2_STATE_M) {
        uint64_t address = client->cache[index].address;

        g_array_append_val(release_addresses, address);
      }
    }
  }
  qemu_mutex_unlock(&client->cache_lock);
  for (index = 0; index < shared_lines->len; index++) {
    CxlMemsimV2CacheLine *line =
        &g_array_index(shared_lines, CxlMemsimV2CacheLine, index);

    if (!cxl_memsim_v2_invalidate_shared_mapping(client, line,
                                                 CXL_MEMSIM_V2_STATE_I, errp)) {
      goto out;
    }
  }
  for (index = 0; index < release_addresses->len; index++) {
    uint64_t address = g_array_index(release_addresses, uint64_t, index);

    if (!cxl_memsim_v2_queue_writeback(client, address, errp)) {
      goto out;
    }
  }
  if (!cxl_memsim_v2_drain_writebacks(client, errp)) {
    goto out;
  }
  /* Publish all direct stores before the persistence request is sent. */
  smp_mb();
  cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_FENCE);
  success =
      cxl_memsim_v2_client_transact(client, &request, &response, timeout_ms,
                                    errp) &&
      cxl_memsim_v2_response_ok(&response, CXL_MEMSIM_V2_OP_FENCE, errp) &&
      response.state == CXL_MEMSIM_V2_STATE_I && response.epoch == 0 &&
      response.payload_len == 0 && response.size == 0;
  if (!success && errp && !*errp) {
    error_setg(errp, "invalid CXLMemSim v2 fence response");
  }
  if (success && shared_ranges) {
    qemu_mutex_lock(&client->cache_lock);
    for (index = 0; index < client->cache_line_count; index++) {
      if (client->cache[index].valid && client->cache[index].shared_range) {
        client->cache[index].valid = false;
        client->cache[index].state = CXL_MEMSIM_V2_STATE_I;
        client->cache[index].epoch = 0;
        client->cache[index].dirty = false;
        client->cache[index].resident_mask = 0;
        client->cache[index].writable_mask = 0;
        client->cache[index].shared_mapping = NULL;
      }
    }
    qemu_mutex_unlock(&client->cache_lock);
  }

out:
  g_rw_lock_writer_unlock(&client->operation_barrier);
  g_array_free(shared_lines, true);
  g_array_free(release_addresses, true);
  return success;
}

bool cxl_memsim_v2_cache_block(CxlMemsimV2Client *client, uint64_t address,
                               bool persist, int timeout_ms, Error **errp) {
  CxlMemsimV2OperationGuard guard;
  uint64_t line_address;
  bool success;

  if (!client || timeout_ms <= 0) {
    error_setg(errp, "invalid CXLMemSim v2 cache-block operation");
    return false;
  }
  if (cxl_memsim_v2_shared_ranges_enabled(client)) {
    return !persist || cxl_memsim_v2_fence(client, timeout_ms, errp);
  }
  line_address = address & ~(uint64_t)(CXL_MEMSIM_V2_LINE_SIZE - 1);
  cxl_memsim_v2_operation_begin(client, line_address, CXL_MEMSIM_V2_LINE_SIZE,
                                &guard);
  success = cxl_memsim_v2_queue_writeback(client, line_address, errp);
  cxl_memsim_v2_operation_end(client, &guard);
  if (!success || !persist) {
    return success;
  }
  return cxl_memsim_v2_fence(client, timeout_ms, errp);
}

static bool cxl_memsim_v2_release_all_cached(CxlMemsimV2Client *client,
                                             Error **errp) {
  GArray *addresses = g_array_new(false, false, sizeof(uint64_t));
  bool success = false;
  size_t index;

  g_rw_lock_writer_lock(&client->operation_barrier);
  if (!cxl_memsim_v2_drain_writebacks(client, errp)) {
    goto out;
  }
  qemu_mutex_lock(&client->cache_lock);
  for (index = 0; index < client->cache_line_count; index++) {
    if (client->cache[index].valid) {
      uint64_t address = client->cache[index].address;

      g_array_append_val(addresses, address);
    }
  }
  qemu_mutex_unlock(&client->cache_lock);
  for (index = 0; index < addresses->len; index++) {
    uint64_t address = g_array_index(addresses, uint64_t, index);

    if (!cxl_memsim_v2_queue_writeback(client, address, errp)) {
      goto out;
    }
  }
  success = cxl_memsim_v2_drain_writebacks(client, errp);

out:
  g_rw_lock_writer_unlock(&client->operation_barrier);
  g_array_free(addresses, true);
  return success;
}

void cxl_memsim_v2_client_free(CxlMemsimV2Client *client) {
  size_t index;

  if (!client) {
    return;
  }
  if (client->started) {
    CxlMemsimV2Frame request;
    CxlMemsimV2Frame response;
    Error *local_err = NULL;
    bool connected;
    bool released = true;
    bool fence_ok = false;
    bool progress_joinable;

    qemu_mutex_lock(&client->state_lock);
    connected = client->connected && client->session_id;
    qemu_mutex_unlock(&client->state_lock);
    if (connected) {
      if (cxl_memsim_v2_shared_ranges_enabled(client)) {
        released = cxl_memsim_v2_release_all_cached(client, &local_err);
      }
      if (released) {
        fence_ok = cxl_memsim_v2_fence(client, client->timeout_ms, &local_err);
      }
      error_free(local_err);
      local_err = NULL;

      qemu_mutex_lock(&client->state_lock);
      connected = fence_ok && client->connected;
      qemu_mutex_unlock(&client->state_lock);
      if (connected) {
        cxl_memsim_v2_frame_init(&request, CXL_MEMSIM_V2_OP_UNREGISTER);
        if (!cxl_memsim_v2_transact_internal(client, &request, &response,
                                             client->timeout_ms, false,
                                             &local_err) ||
            response.status != CXL_MEMSIM_V2_STATUS_OK ||
            response.state != CXL_MEMSIM_V2_STATE_I || response.epoch ||
            response.payload_len) {
          error_free(local_err);
        }
      }
    }
    cxl_memsim_v2_stop_writeback_workers(client);
    qio_channel_shutdown(QIO_CHANNEL(client->socket), QIO_CHANNEL_SHUTDOWN_BOTH,
                         NULL);
    qemu_mutex_lock(&client->state_lock);
    progress_joinable = client->progress_joinable;
    qemu_mutex_unlock(&client->state_lock);
    if (progress_joinable) {
      qemu_thread_join(&client->progress_thread);
      qemu_mutex_lock(&client->state_lock);
      client->progress_joinable = false;
      qemu_mutex_unlock(&client->state_lock);
    }
    qio_channel_close(QIO_CHANNEL(client->socket), NULL);
    object_unref(OBJECT(client->socket));
  }
  qemu_mutex_lock(&client->writeback_lock);
  cxl_memsim_v2_discard_queued_writebacks_locked(client);
  qemu_mutex_unlock(&client->writeback_lock);
  g_hash_table_destroy(client->writeback_pending);
  g_hash_table_destroy(client->pending);
  g_hash_table_destroy(client->completed_retries);
  g_hash_table_destroy(client->shared_mappings);
  g_free(client->cache);
  g_free(client->connection_error);
  g_free(client->writeback_error);
  qemu_cond_destroy(&client->writeback_drained);
  qemu_cond_destroy(&client->writeback_available);
  qemu_mutex_destroy(&client->writeback_lock);
  qemu_mutex_destroy(&client->cache_lock);
  for (index = 0; index < client->operation_gate_count; index++) {
    qemu_mutex_destroy(&client->operation_gates[index]);
  }
  g_free(client->operation_gates);
  g_rw_lock_clear(&client->operation_barrier);
  qemu_mutex_destroy(&client->send_lock);
  qemu_mutex_destroy(&client->request_lock);
  qemu_mutex_destroy(&client->state_lock);
  g_free(client);
}

uint16_t cxl_memsim_v2_client_endpoint(CxlMemsimV2Client *client) {
  return client ? client->endpoint : CXL_MEMSIM_V2_SERVER_ENDPOINT;
}

uint64_t cxl_memsim_v2_client_session(CxlMemsimV2Client *client) {
  uint64_t session = 0;

  if (client) {
    qemu_mutex_lock(&client->state_lock);
    session = client->session_id;
    qemu_mutex_unlock(&client->state_lock);
  }
  return session;
}

unsigned cxl_memsim_v2_client_progress_starts(CxlMemsimV2Client *client) {
  unsigned starts = 0;

  if (client) {
    qemu_mutex_lock(&client->state_lock);
    starts = client->progress_starts;
    qemu_mutex_unlock(&client->state_lock);
  }
  return starts;
}

bool cxl_memsim_v2_client_has_shared_range(CxlMemsimV2Client *client) {
  bool enabled = false;

  if (client) {
    qemu_mutex_lock(&client->state_lock);
    enabled = cxl_memsim_v2_shared_ranges_enabled(client);
    qemu_mutex_unlock(&client->state_lock);
  }
  return enabled;
}

void cxl_memsim_v2_client_stats(CxlMemsimV2Client *client,
                                CxlMemsimV2ClientStats *stats) {
  if (!stats) {
    return;
  }
  memset(stats, 0, sizeof(*stats));
  if (!client) {
    return;
  }
  stats->gets = qatomic_read(&client->stats.gets);
  stats->getm = qatomic_read(&client->stats.getm);
  stats->upgrade = qatomic_read(&client->stats.upgrade);
  stats->puts = qatomic_read(&client->stats.puts);
  stats->putm = qatomic_read(&client->stats.putm);
  stats->fence = qatomic_read(&client->stats.fence);
  stats->resident = qatomic_read(&client->stats.resident);
  stats->gets_ns = qatomic_read(&client->stats.gets_ns);
  stats->getm_ns = qatomic_read(&client->stats.getm_ns);
  stats->upgrade_ns = qatomic_read(&client->stats.upgrade_ns);
  stats->puts_ns = qatomic_read(&client->stats.puts_ns);
  stats->putm_ns = qatomic_read(&client->stats.putm_ns);
  stats->fence_ns = qatomic_read(&client->stats.fence_ns);
  stats->resident_ns = qatomic_read(&client->stats.resident_ns);
}

CxlMemsimV2Client *cxl_memsim_v2_path_client(CxlMemsimV2EndpointPair *endpoints,
                                             CxlMemsimV2Path path) {
  if (!endpoints) {
    return NULL;
  }
  switch (path) {
  case CXL_MEMSIM_V2_PATH_CFMWS_HOST:
    return endpoints->host;
  case CXL_MEMSIM_V2_PATH_BAR2_DEVICE:
    return endpoints->device;
  default:
    return NULL;
  }
}
