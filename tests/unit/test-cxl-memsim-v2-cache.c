#include "qemu/osdep.h"

#include "hw/cxl/cxl_memsim_v2.h"
#include "qapi/error.h"
#include "qemu/module.h"

#include <poll.h>

#define TEST_TIMEOUT_MS 2000
#define NO_FRAME_MS 100
#define TEST_LINE_A UINT64_C(0x1000)
#define TEST_LINE_B UINT64_C(0x2000)
#define TEST_LINE_C (TEST_LINE_A + CXL_MEMSIM_V2_LINE_SIZE)
#define TEST_SHARED_RANGE_A ((uint64_t)CXL_MEMSIM_V2_SHARED_RANGE_SIZE)
#define TEST_SESSION UINT64_C(0x5001)
#define TEST_VALUE_A UINT64_C(0x1122334455667788)
#define TEST_VALUE_B UINT64_C(0xaabbccddeeff0011)

typedef enum CachePeerScript {
  CACHE_PEER_WB_RETAIN,
  CACHE_PEER_DIRTY_DOWNGRADE,
  CACHE_PEER_DIRTY_EVICTION,
  CACHE_PEER_UPGRADE_HITS,
  CACHE_PEER_WRITE_THROUGH,
  CACHE_PEER_FREE_FLUSH,
  CACHE_PEER_FREE_FLUSH_FAILURE,
  CACHE_PEER_FREE_FENCE_FAILURE,
  CACHE_PEER_IMMEDIATE_SNOOP,
  CACHE_PEER_EXCLUSIVE_LOAD,
  CACHE_PEER_DISJOINT_OVERLAP,
  CACHE_PEER_PIPELINED_WRITEBACK,
  CACHE_PEER_SHARED_RANGE,
  CACHE_PEER_SHARED_RESIDENCY_CAPACITY,
} CachePeerScript;

typedef struct CachePeer {
  int fd;
  CachePeerScript script;
  GMutex phase_lock;
  GCond phase_changed;
  unsigned phase;
  int error_code;
  unsigned gets;
  unsigned getm;
  unsigned upgrades;
  unsigned resident;
  unsigned puts;
  unsigned putm;
  unsigned fences;
  unsigned snoop_acks;
  uint64_t written_a;
  uint64_t written_b;
  uint64_t written_c;
  uint16_t teardown_order[3];
  unsigned teardown_count;
  bool unregistered;
  bool immediate_snoop_acked;
  bool pipelined_writeback_observed;
  gint shared_invalidations;
  uint8_t shared_page[CXL_MEMSIM_V2_SHARED_RANGE_SIZE];
} CachePeer;

typedef struct CacheStoreWorker {
  CxlMemsimV2Client *client;
  uint64_t address;
  uint64_t value;
  char *error;
  bool success;
} CacheStoreWorker;

static bool cache_peer_uses_shared_ranges(const CachePeer *peer) {
  return peer->script == CACHE_PEER_SHARED_RANGE ||
         peer->script == CACHE_PEER_SHARED_RESIDENCY_CAPACITY;
}

static void put_le16(uint8_t *bytes, size_t offset, uint16_t value) {
  bytes[offset] = value;
  bytes[offset + 1] = value >> 8;
}

static void put_le32(uint8_t *bytes, size_t offset, uint32_t value) {
  size_t i;

  for (i = 0; i < sizeof(value); i++) {
    bytes[offset + i] = value >> (i * 8);
  }
}

static void put_le64(uint8_t *bytes, size_t offset, uint64_t value) {
  size_t i;

  for (i = 0; i < sizeof(value); i++) {
    bytes[offset + i] = value >> (i * 8);
  }
}

static uint16_t get_le16(const uint8_t *bytes, size_t offset) {
  return bytes[offset] | (uint16_t)bytes[offset + 1] << 8;
}

static uint32_t get_le32(const uint8_t *bytes, size_t offset) {
  uint32_t value = 0;
  size_t i;

  for (i = 0; i < sizeof(value); i++) {
    value |= (uint32_t)bytes[offset + i] << (i * 8);
  }
  return value;
}

static uint64_t get_le64(const uint8_t *bytes, size_t offset) {
  uint64_t value = 0;
  size_t i;

  for (i = 0; i < sizeof(value); i++) {
    value |= (uint64_t)bytes[offset + i] << (i * 8);
  }
  return value;
}

static bool read_all_timeout(int fd, uint8_t *bytes, size_t length) {
  size_t offset = 0;

  while (offset < length) {
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN,
    };
    ssize_t received;

    if (poll(&pfd, 1, TEST_TIMEOUT_MS) != 1) {
      return false;
    }
    do {
      received = recv(fd, bytes + offset, length - offset, 0);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
      return false;
    }
    offset += received;
  }
  return true;
}

static bool write_all(int fd, const uint8_t *bytes, size_t length) {
  size_t offset = 0;

  while (offset < length) {
    ssize_t sent;

    do {
      sent = send(fd, bytes + offset, length - offset, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);
    if (sent <= 0) {
      return false;
    }
    offset += sent;
  }
  return true;
}

static void init_wire_frame(uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE],
                            uint16_t opcode) {
  memset(frame, 0, CXL_MEMSIM_V2_FRAME_SIZE);
  put_le32(frame, 0, CXL_MEMSIM_V2_MAGIC);
  put_le16(frame, 4, CXL_MEMSIM_V2_VERSION);
  put_le16(frame, 6, opcode);
}

static bool send_registration_response(CachePeer *peer,
                                       const uint8_t *request) {
  uint8_t response[CXL_MEMSIM_V2_FRAME_SIZE];

  init_wire_frame(response, CXL_MEMSIM_V2_OP_RESPONSE);
  response[14] = CXL_MEMSIM_V2_ACK_MODEL;
  put_le16(response, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
  put_le16(response, 18, get_le16(request, 16));
  put_le64(response, 40, TEST_SESSION);
  put_le64(response, 64,
           CXL_MEMSIM_V2_CAP_MODEL_SNOOP |
               (cache_peer_uses_shared_ranges(peer)
                    ? CXL_MEMSIM_V2_CAP_SHARED_RANGE
                    : 0));
  put_le64(response, 72, get_le64(request, 72));
  put_le64(response, 80, get_le64(request, 80));
  put_le64(response, 88, 1);
  put_le32(response, 96, CXL_MEMSIM_V2_LINE_SIZE);
  return write_all(peer->fd, response, sizeof(response));
}

static bool send_response(CachePeer *peer, const uint8_t *request,
                          uint8_t state, uint64_t epoch, const uint8_t *line,
                          uint64_t old_value) {
  uint8_t response[CXL_MEMSIM_V2_FRAME_SIZE];

  init_wire_frame(response, CXL_MEMSIM_V2_OP_RESPONSE);
  response[15] = state;
  put_le16(response, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
  put_le16(response, 18, get_le16(request, 16));
  put_le64(response, 24, get_le64(request, 24));
  put_le64(response, 40, get_le64(request, 40));
  put_le64(response, 48, get_le64(request, 48));
  put_le64(response, 56, epoch);
  put_le64(response, 88, old_value);
  if (get_le32(request, 96) == CXL_MEMSIM_V2_SHARED_RANGE_SIZE) {
    put_le32(response, 96, CXL_MEMSIM_V2_SHARED_RANGE_SIZE);
    switch (get_le16(request, 6)) {
    case CXL_MEMSIM_V2_OP_GETS:
    case CXL_MEMSIM_V2_OP_GETM:
    case CXL_MEMSIM_V2_OP_UPGRADE:
    case CXL_MEMSIM_V2_OP_RESIDENT:
      put_le64(response, 72, get_le64(request, 72));
      put_le64(response, 80, get_le64(request, 80));
      break;
    default:
      break;
    }
  }
  if (line) {
    put_le16(response, 20, CXL_MEMSIM_V2_LINE_SIZE);
    memcpy(response + 104, line, CXL_MEMSIM_V2_LINE_SIZE);
  }
  return write_all(peer->fd, response, sizeof(response));
}

static bool send_error_response(CachePeer *peer, const uint8_t *request,
                                uint16_t status) {
  uint8_t response[CXL_MEMSIM_V2_FRAME_SIZE];

  init_wire_frame(response, CXL_MEMSIM_V2_OP_RESPONSE);
  put_le16(response, 12, status);
  put_le16(response, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
  put_le16(response, 18, get_le16(request, 16));
  put_le64(response, 24, get_le64(request, 24));
  put_le64(response, 40, get_le64(request, 40));
  put_le64(response, 48, get_le64(request, 48));
  return write_all(peer->fd, response, sizeof(response));
}

static bool expect_frame(CachePeer *peer, uint16_t opcode,
                         uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
  if (!read_all_timeout(peer->fd, frame, CXL_MEMSIM_V2_FRAME_SIZE)) {
    g_test_message("timed out waiting for opcode 0x%x", opcode);
    peer->error_code = EPROTO;
    return false;
  }
  if (get_le32(frame, 0) != CXL_MEMSIM_V2_MAGIC ||
      get_le16(frame, 6) != opcode ||
      get_le16(frame, 16) != CXL_MEMSIM_V2_DEVICE_ENDPOINT ||
      get_le64(frame, 40) != TEST_SESSION) {
    g_test_message("expected opcode 0x%x, got 0x%x host=%u session=%" PRIu64,
                   opcode, get_le16(frame, 6), get_le16(frame, 16),
                   get_le64(frame, 40));
    peer->error_code = EPROTO;
    return false;
  }
  switch (opcode) {
  case CXL_MEMSIM_V2_OP_GETS:
    peer->gets++;
    break;
  case CXL_MEMSIM_V2_OP_GETM:
    peer->getm++;
    break;
  case CXL_MEMSIM_V2_OP_UPGRADE:
    peer->upgrades++;
    break;
  case CXL_MEMSIM_V2_OP_RESIDENT:
    peer->resident++;
    break;
  case CXL_MEMSIM_V2_OP_PUTS:
    peer->puts++;
    break;
  case CXL_MEMSIM_V2_OP_PUTM:
    peer->putm++;
    break;
  case CXL_MEMSIM_V2_OP_FENCE:
    peer->fences++;
    break;
  case CXL_MEMSIM_V2_OP_SNOOP_ACK:
    peer->snoop_acks++;
    break;
  default:
    break;
  }
  return true;
}

static bool no_frame_available(CachePeer *peer) {
  struct pollfd pfd = {
      .fd = peer->fd,
      .events = POLLIN,
  };
  int ready;

  do {
    ready = poll(&pfd, 1, NO_FRAME_MS);
  } while (ready < 0 && errno == EINTR);
  if (ready != 0) {
    peer->error_code = EPROTO;
    return false;
  }
  return true;
}

static void set_phase(CachePeer *peer, unsigned phase) {
  g_mutex_lock(&peer->phase_lock);
  peer->phase = MAX(peer->phase, phase);
  g_cond_broadcast(&peer->phase_changed);
  g_mutex_unlock(&peer->phase_lock);
}

static bool wait_phase(CachePeer *peer, unsigned phase) {
  int64_t deadline =
      g_get_monotonic_time() + TEST_TIMEOUT_MS * G_TIME_SPAN_MILLISECOND;
  bool reached;

  g_mutex_lock(&peer->phase_lock);
  while (peer->phase < phase && !peer->error_code) {
    if (!g_cond_wait_until(&peer->phase_changed, &peer->phase_lock, deadline)) {
      break;
    }
  }
  reached = peer->phase >= phase;
  g_mutex_unlock(&peer->phase_lock);
  return reached;
}

static bool expect_register(CachePeer *peer,
                            uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
  if (!read_all_timeout(peer->fd, frame, CXL_MEMSIM_V2_FRAME_SIZE) ||
      get_le16(frame, 6) != CXL_MEMSIM_V2_OP_REGISTER ||
      get_le16(frame, 16) != CXL_MEMSIM_V2_DEVICE_ENDPOINT ||
      (cache_peer_uses_shared_ranges(peer) &&
       (get_le64(frame, 64) & CXL_MEMSIM_V2_CAP_SHARED_RANGE) == 0) ||
      !send_registration_response(peer, frame)) {
    peer->error_code = EPROTO;
    return false;
  }
  return true;
}

static bool expect_fence(CachePeer *peer,
                         uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
  return expect_frame(peer, CXL_MEMSIM_V2_OP_FENCE, frame) &&
         send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0);
}

static bool expect_unregister(CachePeer *peer,
                              uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_UNREGISTER, frame) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0)) {
    return false;
  }
  peer->unregistered = true;
  return true;
}

static bool expect_clean_teardown(CachePeer *peer,
                                  uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
  return expect_fence(peer, frame) && expect_unregister(peer, frame);
}

static bool expect_putm(CachePeer *peer,
                        uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE],
                        uint64_t address, uint64_t value, uint64_t epoch) {
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) ||
      get_le64(frame, 48) != address ||
      get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE ||
      get_le64(frame, 104) != value) {
    g_test_message("PUTM expected addr=%" PRIx64 " value=%" PRIx64
                   ", got addr=%" PRIx64 " length=%u value=%" PRIx64,
                   address, value, get_le64(frame, 48), get_le16(frame, 20),
                   get_le64(frame, 104));
    peer->error_code = EPROTO;
    return false;
  }
  if (address == TEST_LINE_A) {
    peer->written_a = get_le64(frame, 104);
  } else if (address == TEST_LINE_B) {
    peer->written_b = get_le64(frame, 104);
  } else if (address == TEST_LINE_C) {
    peer->written_c = get_le64(frame, 104);
  }
  return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, epoch, NULL, 0);
}

static bool expect_disjoint_putm(CachePeer *peer,
                                 uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE],
                                 bool *seen_a, bool *seen_c) {
  uint64_t address;
  uint64_t value;

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame)) {
    return false;
  }
  address = get_le64(frame, 48);
  value = get_le64(frame, 104);
  if (get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE ||
      (address == TEST_LINE_A && (*seen_a || value != TEST_VALUE_A)) ||
      (address == TEST_LINE_C && (*seen_c || value != TEST_VALUE_B)) ||
      (address != TEST_LINE_A && address != TEST_LINE_C)) {
    peer->error_code = EPROTO;
    return false;
  }
  if (address == TEST_LINE_A) {
    *seen_a = true;
    peer->written_a = value;
  } else {
    *seen_c = true;
    peer->written_c = value;
  }
  return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I,
                       get_le64(frame, 56) + 1, NULL, 0);
}

static bool run_wb_retain_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
      !no_frame_available(peer)) {
    return false;
  }
  set_phase(peer, 1);
  return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_B, 2) &&
         expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_exclusive_load_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  put_le64(line, 0, TEST_VALUE_A);
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  set_phase(peer, 1);
  return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2) &&
         expect_clean_teardown(peer, frame);
}

static bool send_dirty_downgrade(CachePeer *peer) {
  uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];

  init_wire_frame(snoop, CXL_MEMSIM_V2_OP_SNP_DATA_DOWNGRADE);
  put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
  put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
  put_le64(snoop, 32, 77);
  put_le64(snoop, 40, TEST_SESSION);
  put_le64(snoop, 48, TEST_LINE_A);
  put_le64(snoop, 56, 2);
  return write_all(peer->fd, snoop, sizeof(snoop));
}

static bool run_dirty_downgrade_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  set_phase(peer, 1);
  if (!wait_phase(peer, 2) || !send_dirty_downgrade(peer) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
      get_le64(frame, 32) != 77 ||
      get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
      frame[14] != CXL_MEMSIM_V2_ACK_MODEL ||
      frame[15] != CXL_MEMSIM_V2_STATE_S ||
      get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE ||
      get_le64(frame, 104) != TEST_VALUE_A) {
    peer->error_code = EPROTO;
    return false;
  }
  set_phase(peer, 3);
  return expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_dirty_eviction_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
      !no_frame_available(peer)) {
    return false;
  }
  set_phase(peer, 1);
  if (!expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_B ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
      !no_frame_available(peer)) {
    return false;
  }
  set_phase(peer, 2);
  return expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 2) &&
         expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_upgrade_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line_a[CXL_MEMSIM_V2_LINE_SIZE] = {0};
  uint8_t line_b[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  put_le64(line_a, 0, 1);
  put_le64(line_b, 0, 2);
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 1, line_a, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      frame[15] != CXL_MEMSIM_V2_STATE_E || get_le64(frame, 56) != 1 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 2, NULL, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
      get_le64(frame, 48) != TEST_LINE_B ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 5, line_b, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) ||
      get_le64(frame, 48) != TEST_LINE_B ||
      frame[15] != CXL_MEMSIM_V2_STATE_S || get_le64(frame, 56) != 5 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 6, NULL, 0) ||
      !no_frame_available(peer)) {
    return false;
  }
  set_phase(peer, 1);
  return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 3) &&
         expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 7) &&
         expect_clean_teardown(peer, frame);
}

static bool run_write_through_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
      !expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2)) {
    return false;
  }
  set_phase(peer, 1);
  return expect_clean_teardown(peer, frame);
}

static bool record_teardown_frame(CachePeer *peer, const uint8_t *frame,
                                  uint16_t opcode) {
  if (peer->teardown_count >= G_N_ELEMENTS(peer->teardown_order)) {
    peer->error_code = EOVERFLOW;
    return false;
  }
  peer->teardown_order[peer->teardown_count++] = opcode;
  return true;
}

static bool run_free_flush_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  set_phase(peer, 1);
  if (!expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2) ||
      !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_PUTM) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_FENCE, frame) ||
      !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_FENCE) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_UNREGISTER, frame) ||
      !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_UNREGISTER) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0)) {
    return false;
  }
  peer->unregistered = true;
  return true;
}

static bool run_free_flush_failure_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  set_phase(peer, 1);
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE ||
      get_le64(frame, 104) != TEST_VALUE_A ||
      !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_PUTM)) {
    return false;
  }
  peer->written_a = get_le64(frame, 104);
  return send_error_response(peer, frame, CXL_MEMSIM_V2_STATUS_IO_ERROR);
}

static bool run_free_fence_failure_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  set_phase(peer, 1);
  if (!expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2) ||
      !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_PUTM) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_FENCE, frame) ||
      !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_FENCE) ||
      !send_error_response(peer, frame, CXL_MEMSIM_V2_STATUS_IO_ERROR)) {
    return false;
  }
  return true;
}

static bool run_immediate_snoop_script(CachePeer *peer, uint8_t *frame) {
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
  uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];

  put_le64(line, 0, TEST_VALUE_A);
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  init_wire_frame(snoop, CXL_MEMSIM_V2_OP_SNP_DATA_INV);
  put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
  put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
  put_le64(snoop, 32, 91);
  put_le64(snoop, 40, TEST_SESSION);
  put_le64(snoop, 48, TEST_LINE_A);
  put_le64(snoop, 56, 2);
  if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
      get_le64(frame, 32) != 91 ||
      get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
      frame[15] != CXL_MEMSIM_V2_STATE_I ||
      get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE ||
      get_le64(frame, 104) != TEST_VALUE_A) {
    peer->error_code = EPROTO;
    return false;
  }
  peer->immediate_snoop_acked = true;

  memset(line, 0, sizeof(line));
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 3, line, 0) ||
      !expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_B, 4)) {
    return false;
  }
  return expect_clean_teardown(peer, frame);
}

static bool run_disjoint_overlap_script(CachePeer *peer, uint8_t *frame) {
  uint8_t second[CXL_MEMSIM_V2_FRAME_SIZE];
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
  uint64_t first_address;
  uint64_t second_address;
  bool seen_a = false;
  bool seen_c = false;

  /* Do not answer the first GETM until the independent set reaches us. */
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, second)) {
    return false;
  }
  first_address = get_le64(frame, 48);
  second_address = get_le64(second, 48);
  if (get_le64(second, 24) != get_le64(frame, 24) + 1 ||
      first_address == second_address ||
      (first_address != TEST_LINE_A && first_address != TEST_LINE_C) ||
      (second_address != TEST_LINE_A && second_address != TEST_LINE_C) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
      !send_response(peer, second, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    peer->error_code = EPROTO;
    return false;
  }
  set_phase(peer, 1);
  if (!expect_disjoint_putm(peer, frame, &seen_a, &seen_c) ||
      !expect_disjoint_putm(peer, frame, &seen_a, &seen_c) || !seen_a ||
      !seen_c) {
    return false;
  }
  return expect_clean_teardown(peer, frame);
}

static bool run_pipelined_writeback_script(CachePeer *peer, uint8_t *frame) {
  uint8_t second[CXL_MEMSIM_V2_FRAME_SIZE];
  uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
  uint64_t first_address;
  uint64_t second_address;

  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_A ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_LINE_C ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
    return false;
  }
  set_phase(peer, 1);

  /* Both PUTMs must arrive before either is acknowledged. */
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, second)) {
    return false;
  }
  first_address = get_le64(frame, 48);
  second_address = get_le64(second, 48);
  if (get_le64(second, 24) != get_le64(frame, 24) + 1 ||
      first_address == second_address ||
      (first_address != TEST_LINE_A && first_address != TEST_LINE_C) ||
      (second_address != TEST_LINE_A && second_address != TEST_LINE_C) ||
      (first_address == TEST_LINE_A && get_le64(frame, 104) != TEST_VALUE_A) ||
      (first_address == TEST_LINE_C && get_le64(frame, 104) != TEST_VALUE_B) ||
      (second_address == TEST_LINE_A &&
       get_le64(second, 104) != TEST_VALUE_A) ||
      (second_address == TEST_LINE_C &&
       get_le64(second, 104) != TEST_VALUE_B)) {
    peer->error_code = EPROTO;
    return false;
  }
  peer->pipelined_writeback_observed = true;
  if (!send_response(peer, second, CXL_MEMSIM_V2_STATE_I,
                     get_le64(second, 56) + 1, NULL, 0) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_I,
                     get_le64(frame, 56) + 1, NULL, 0)) {
    return false;
  }
  return expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_shared_range_script(CachePeer *peer, uint8_t *frame) {
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      get_le16(frame, 20) != 0 || get_le64(frame, 80) != UINT64_C(1) ||
      get_le64(frame, 72) != 0 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 1, NULL, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_RESIDENT, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      frame[15] != CXL_MEMSIM_V2_STATE_S || get_le64(frame, 56) != 1 ||
      get_le64(frame, 80) !=
          (UINT64_C(1) << (CXL_MEMSIM_V2_RESIDENCY_PAGE_COUNT - 1)) ||
      get_le64(frame, 72) != 0 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 1, NULL, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      frame[15] != CXL_MEMSIM_V2_STATE_S || get_le64(frame, 56) != 1 ||
      get_le64(frame, 80) != UINT64_C(1) ||
      get_le64(frame, 72) != UINT64_C(1) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 2, NULL, 0)) {
    return false;
  }
  set_phase(peer, 1);
  if (!expect_fence(peer, frame) || !no_frame_available(peer)) {
    return false;
  }
  set_phase(peer, 2);
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      frame[15] != CXL_MEMSIM_V2_STATE_I || get_le64(frame, 56) != 0 ||
      get_le64(frame, 80) !=
          (UINT64_C(1) << (CXL_MEMSIM_V2_RESIDENCY_PAGE_COUNT - 1)) ||
      get_le64(frame, 72) != 0 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 4, NULL, 0)) {
    return false;
  }
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      get_le16(frame, 20) != 0 || frame[15] != CXL_MEMSIM_V2_STATE_E ||
      get_le64(frame, 56) != 4 || get_le64(frame, 80) != UINT64_C(1) ||
      get_le64(frame, 72) != UINT64_C(1) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 5, NULL, 0)) {
    return false;
  }
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      get_le16(frame, 20) != 0 || frame[15] != CXL_MEMSIM_V2_STATE_M ||
      get_le64(frame, 56) != 5 ||
      get_le64(frame, 80) != CXL_MEMSIM_V2_RESIDENCY_FULL_MASK ||
      get_le64(frame, 72) !=
          (CXL_MEMSIM_V2_RESIDENCY_FULL_MASK & ~UINT64_C(1)) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 6, NULL, 0)) {
    return false;
  }
  set_phase(peer, 3);
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le32(frame, 96) != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      get_le16(frame, 20) != 0 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 7, NULL, 0) ||
      !expect_fence(peer, frame) || !expect_unregister(peer, frame)) {
    return false;
  }
  return true;
}

static bool run_shared_residency_capacity_script(CachePeer *peer,
                                                 uint8_t *frame) {
  unsigned index;

  /* Fill fifteen of the sixteen permission entries with one resident page
   * each.  A second page in range A fills the 64 KiB residency budget. */
  for (index = 0; index < 15; ++index) {
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
        get_le64(frame, 48) !=
            TEST_SHARED_RANGE_A +
                index * (uint64_t)CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
        get_le64(frame, 80) != UINT64_C(1) || get_le64(frame, 72) != 0 ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 1, NULL, 0)) {
      return false;
    }
  }
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_RESIDENT, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le64(frame, 80) != UINT64_C(1) << 8 ||
      get_le64(frame, 72) != 0 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 1, NULL, 0)) {
    return false;
  }

  /* The next page drops only B's 4 KiB residency, retaining its S
   * permission.  It must therefore use Resident release, never PUTS. */
  if (!expect_frame(peer, CXL_MEMSIM_V2_OP_RESIDENT, frame) ||
      get_le64(frame, 48) !=
          TEST_SHARED_RANGE_A + CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      get_le64(frame, 80) != 0 || get_le64(frame, 72) != UINT64_C(1) ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 1, NULL, 0) ||
      !expect_frame(peer, CXL_MEMSIM_V2_OP_RESIDENT, frame) ||
      get_le64(frame, 48) != TEST_SHARED_RANGE_A ||
      get_le64(frame, 80) != UINT64_C(1) << 3 ||
      get_le64(frame, 72) != 0 ||
      !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 1, NULL, 0) ||
      !expect_fence(peer, frame) || !no_frame_available(peer)) {
    return false;
  }
  set_phase(peer, 1);
  return expect_clean_teardown(peer, frame);
}

static bool shared_range_access(void *opaque, void *mapping, uint64_t address,
                                uint8_t *data, unsigned size, bool write,
                                Error **errp) {
  CachePeer *peer = opaque;
  uint64_t offset;

  if (!peer || mapping != peer || !data || address < TEST_SHARED_RANGE_A ||
      size > CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      address - TEST_SHARED_RANGE_A > CXL_MEMSIM_V2_SHARED_RANGE_SIZE - size) {
    error_setg(errp, "invalid test shared-range mapping access");
    return false;
  }
  offset = address - TEST_SHARED_RANGE_A;
  if (write) {
    memcpy(peer->shared_page + offset, data, size);
  } else {
    memcpy(data, peer->shared_page + offset, size);
  }
  return true;
}

static bool shared_range_invalidate(void *opaque, void *mapping,
                                    uint64_t address, unsigned size,
                                    CxlMemsimV2LineState old_state,
                                    CxlMemsimV2LineState new_state,
                                    Error **errp) {
  CachePeer *peer = opaque;

  if (!peer || mapping != peer ||
      (peer->script == CACHE_PEER_SHARED_RANGE &&
       address != TEST_SHARED_RANGE_A) ||
      (peer->script == CACHE_PEER_SHARED_RESIDENCY_CAPACITY &&
       (address < TEST_SHARED_RANGE_A ||
        address >= TEST_SHARED_RANGE_A +
                       15 * (uint64_t)CXL_MEMSIM_V2_SHARED_RANGE_SIZE)) ||
      size != CXL_MEMSIM_V2_SHARED_RANGE_SIZE ||
      (peer->script == CACHE_PEER_SHARED_RANGE &&
       (old_state != CXL_MEMSIM_V2_STATE_M ||
        (new_state != CXL_MEMSIM_V2_STATE_M &&
         new_state != CXL_MEMSIM_V2_STATE_I))) ||
      (peer->script == CACHE_PEER_SHARED_RESIDENCY_CAPACITY &&
       (old_state != CXL_MEMSIM_V2_STATE_S ||
        new_state != CXL_MEMSIM_V2_STATE_I))) {
    error_setg(errp, "invalid test shared-range invalidation");
    return false;
  }
  g_atomic_int_inc(&peer->shared_invalidations);
  return true;
}

static gpointer cache_peer_thread(gpointer opaque) {
  CachePeer *peer = opaque;
  uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE];
  bool success = false;

  if (!expect_register(peer, frame)) {
    goto out;
  }
  switch (peer->script) {
  case CACHE_PEER_WB_RETAIN:
    success = run_wb_retain_script(peer, frame);
    break;
  case CACHE_PEER_DIRTY_DOWNGRADE:
    success = run_dirty_downgrade_script(peer, frame);
    break;
  case CACHE_PEER_DIRTY_EVICTION:
    success = run_dirty_eviction_script(peer, frame);
    break;
  case CACHE_PEER_UPGRADE_HITS:
    success = run_upgrade_script(peer, frame);
    break;
  case CACHE_PEER_WRITE_THROUGH:
    success = run_write_through_script(peer, frame);
    break;
  case CACHE_PEER_FREE_FLUSH:
    success = run_free_flush_script(peer, frame);
    break;
  case CACHE_PEER_FREE_FLUSH_FAILURE:
    success = run_free_flush_failure_script(peer, frame);
    break;
  case CACHE_PEER_FREE_FENCE_FAILURE:
    success = run_free_fence_failure_script(peer, frame);
    break;
  case CACHE_PEER_IMMEDIATE_SNOOP:
    success = run_immediate_snoop_script(peer, frame);
    break;
  case CACHE_PEER_EXCLUSIVE_LOAD:
    success = run_exclusive_load_script(peer, frame);
    break;
  case CACHE_PEER_DISJOINT_OVERLAP:
    success = run_disjoint_overlap_script(peer, frame);
    break;
  case CACHE_PEER_PIPELINED_WRITEBACK:
    success = run_pipelined_writeback_script(peer, frame);
    break;
  case CACHE_PEER_SHARED_RANGE:
    success = run_shared_range_script(peer, frame);
    break;
  case CACHE_PEER_SHARED_RESIDENCY_CAPACITY:
    success = run_shared_residency_capacity_script(peer, frame);
    break;
  }
  if (!success && !peer->error_code) {
    peer->error_code = EPROTO;
  }
  if (success) {
    uint8_t unexpected;
    ssize_t received;

    do {
      received = recv(peer->fd, &unexpected, sizeof(unexpected), 0);
    } while (received < 0 && errno == EINTR);
    if (received > 0) {
      g_test_message("unexpected frame after cache peer script");
      peer->error_code = EPROTO;
    }
  }

out:
  set_phase(peer, UINT_MAX);
  close(peer->fd);
  return NULL;
}

static CxlMemsimV2Client *start_cache_client(CachePeer *peer,
                                             uint32_t cache_capacity,
                                             uint16_t cache_ways,
                                             GThread **peer_thread) {
  int sockets[2];
  CxlMemsimV2Client *client;
  Error *err = NULL;

  g_mutex_init(&peer->phase_lock);
  g_cond_init(&peer->phase_changed);
  g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
  peer->fd = sockets[1];
  *peer_thread = g_thread_new("memsim-v2-cache-peer", cache_peer_thread, peer);
  client = cxl_memsim_v2_client_new(CXL_MEMSIM_V2_DEVICE_ENDPOINT, NULL, NULL);
  g_assert_nonnull(client);
  if (peer->script == CACHE_PEER_WRITE_THROUGH) {
    g_assert_true(cxl_memsim_v2_client_set_write_policy(
        client, CXL_MEMSIM_V2_WRITE_THROUGH, &err));
    g_assert_null(err);
  }
  if (cache_peer_uses_shared_ranges(peer)) {
    g_assert_true(cxl_memsim_v2_client_set_shared_access(
        client, shared_range_access, peer, &err));
    g_assert_null(err);
    g_assert_true(cxl_memsim_v2_client_set_shared_invalidate(
        client, shared_range_invalidate, peer, &err));
    g_assert_null(err);
  }
  g_assert_true(cxl_memsim_v2_client_start_fd(
      client, sockets[0], cache_capacity, cache_ways, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  return client;
}

static void finish_cache_test(CachePeer *peer, GThread *peer_thread,
                              CxlMemsimV2Client *client) {
  cxl_memsim_v2_client_free(client);
  g_thread_join(peer_thread);
  g_assert_cmpint(peer->error_code, ==, 0);
  g_cond_clear(&peer->phase_changed);
  g_mutex_clear(&peer->phase_lock);
}

static gpointer cache_store_worker(gpointer opaque) {
  CacheStoreWorker *worker = opaque;
  Error *err = NULL;

  worker->success = cxl_memsim_v2_store(worker->client, worker->address, 8,
                                        worker->value, TEST_TIMEOUT_MS, &err);
  if (err) {
    worker->error = g_strdup(error_get_pretty(err));
    error_free(err);
  }
  return NULL;
}

static void test_wb_store_and_m_hit_do_not_putm_until_fence(void) {
  CachePeer peer = {
      .script = CACHE_PEER_WB_RETAIN,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;
  bool fenced;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_B,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));
  fenced = cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err);
  if (!fenced && err) {
    g_test_message("fence failed: %s", error_get_pretty(err));
  }
  g_assert_true(fenced);
  g_assert_null(err);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.getm, ==, 1);
  g_assert_cmpuint(peer.putm, ==, 1);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_B);
}

static void test_cache_block_writeback_reaches_persistence_fence(void) {
  CachePeer peer = {
      .script = CACHE_PEER_WB_RETAIN,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_B,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));
  g_assert_true(cxl_memsim_v2_cache_block(client, TEST_LINE_A, true,
                                          TEST_TIMEOUT_MS, &err));
  g_assert_null(err);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.putm, ==, 1);
  g_assert_cmpuint(peer.fences, ==, 2);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_B);
}

static void test_dirty_owner_snoop_downgrade_returns_full_line(void) {
  CachePeer peer = {
      .script = CACHE_PEER_DIRTY_DOWNGRADE,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  set_phase(&peer, 2);
  g_assert_true(wait_phase(&peer, 3));
  g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.snoop_acks, ==, 1);
  g_assert_cmpuint(peer.putm, ==, 0);
}

static void test_exclusive_load_uses_getm(void) {
  CachePeer peer = {
      .script = CACHE_PEER_EXCLUSIVE_LOAD,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;
  uint64_t value = 0;

  g_assert_true(cxl_memsim_v2_load_exclusive(client, TEST_LINE_A, 8, &value,
                                             TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmphex(value, ==, TEST_VALUE_A);
  g_assert_true(wait_phase(&peer, 1));

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.gets, ==, 0);
  g_assert_cmpuint(peer.getm, ==, 1);
}

static void test_dirty_lru_eviction_is_only_early_putm(void) {
  CachePeer peer = {
      .script = CACHE_PEER_DIRTY_EVICTION,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;
  bool fenced;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));
  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 2));
  fenced = cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err);
  if (!fenced && err) {
    g_test_message("eviction fence failed: %s", error_get_pretty(err));
  }
  g_assert_true(fenced);
  g_assert_null(err);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.getm, ==, 2);
  g_assert_cmpuint(peer.putm, ==, 2);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
  g_assert_cmphex(peer.written_b, ==, TEST_VALUE_B);
}

static void test_e_and_s_store_hits_use_explicit_upgrade(void) {
  CachePeer peer = {
      .script = CACHE_PEER_UPGRADE_HITS,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, 2 * CXL_MEMSIM_V2_LINE_SIZE, 2, &peer_thread);
  Error *err = NULL;
  uint64_t value = 0;

  g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value,
                                   TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmpuint(value, ==, 1);
  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value,
                                   TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmphex(value, ==, TEST_VALUE_A);

  g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_B, 8, &value,
                                   TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmpuint(value, ==, 2);
  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.gets, ==, 2);
  g_assert_cmpuint(peer.getm, ==, 0);
  g_assert_cmpuint(peer.upgrades, ==, 2);
  g_assert_cmpuint(peer.putm, ==, 2);
}

static void test_write_through_policy_putm_after_store(void) {
  CachePeer peer = {
      .script = CACHE_PEER_WRITE_THROUGH,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.getm, ==, 1);
  g_assert_cmpuint(peer.putm, ==, 1);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
}

static void test_free_flushes_dirty_data_then_unregisters(void) {
  CachePeer peer = {
      .script = CACHE_PEER_FREE_FLUSH,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
  g_assert_cmpuint(peer.teardown_count, ==, 3);
  g_assert_cmpuint(peer.teardown_order[0], ==, CXL_MEMSIM_V2_OP_PUTM);
  g_assert_cmpuint(peer.teardown_order[1], ==, CXL_MEMSIM_V2_OP_FENCE);
  g_assert_cmpuint(peer.teardown_order[2], ==, CXL_MEMSIM_V2_OP_UNREGISTER);
  g_assert_true(peer.unregistered);
}

static void test_free_flush_failure_does_not_unregister(void) {
  CachePeer peer = {
      .script = CACHE_PEER_FREE_FLUSH_FAILURE,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
  g_assert_cmpuint(peer.teardown_count, ==, 1);
  g_assert_cmpuint(peer.teardown_order[0], ==, CXL_MEMSIM_V2_OP_PUTM);
  g_assert_false(peer.unregistered);
}

static void test_free_fence_failure_does_not_unregister(void) {
  CachePeer peer = {
      .script = CACHE_PEER_FREE_FENCE_FAILURE,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
  g_assert_cmpuint(peer.teardown_count, ==, 2);
  g_assert_cmpuint(peer.teardown_order[0], ==, CXL_MEMSIM_V2_OP_PUTM);
  g_assert_cmpuint(peer.teardown_order[1], ==, CXL_MEMSIM_V2_OP_FENCE);
  g_assert_false(peer.unregistered);
}

static void test_immediate_post_grant_snoop_observes_installed_line(void) {
  CachePeer peer = {
      .script = CACHE_PEER_IMMEDIATE_SNOOP,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_B,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  finish_cache_test(&peer, peer_thread, client);
  g_assert_true(peer.immediate_snoop_acked);
  g_assert_cmpuint(peer.getm, ==, 2);
}

static void test_disjoint_cache_sets_issue_concurrent_requests(void) {
  CachePeer peer = {
      .script = CACHE_PEER_DISJOINT_OVERLAP,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, 4 * CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  CacheStoreWorker first = {
      .client = client,
      .address = TEST_LINE_A,
      .value = TEST_VALUE_A,
  };
  CacheStoreWorker second = {
      .client = client,
      .address = TEST_LINE_C,
      .value = TEST_VALUE_B,
  };
  GThread *first_thread =
      g_thread_new("memsim-v2-store-a", cache_store_worker, &first);
  GThread *second_thread =
      g_thread_new("memsim-v2-store-c", cache_store_worker, &second);

  g_thread_join(first_thread);
  g_thread_join(second_thread);
  if (first.error) {
    g_test_message("first disjoint store failed: %s", first.error);
  }
  if (second.error) {
    g_test_message("second disjoint store failed: %s", second.error);
  }
  g_assert_true(first.success);
  g_assert_true(second.success);
  g_assert_true(wait_phase(&peer, 1));
  g_free(first.error);
  g_free(second.error);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.getm, ==, 2);
  g_assert_cmpuint(peer.putm, ==, 2);
  g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
  g_assert_cmphex(peer.written_c, ==, TEST_VALUE_B);
}

static void test_cache_block_writebacks_are_pipelined_before_fence(void) {
  CachePeer peer = {
      .script = CACHE_PEER_PIPELINED_WRITEBACK,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client =
      start_cache_client(&peer, 4 * CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
  Error *err = NULL;

  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_C, 8, TEST_VALUE_B,
                                    TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));
  g_assert_true(cxl_memsim_v2_cache_block(client, TEST_LINE_A, false,
                                          TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_cache_block(client, TEST_LINE_C, false,
                                          TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_true(peer.pipelined_writeback_observed);
  g_assert_cmpuint(peer.putm, ==, 2);
  g_assert_cmpuint(peer.fences, ==, 2);
}

static void test_shared_range_fence_releases_then_reacquires_grant(void) {
  CachePeer peer = {
      .script = CACHE_PEER_SHARED_RANGE,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client = start_cache_client(
      &peer, CXL_MEMSIM_V2_SHARED_RANGE_SIZE, 1, &peer_thread);
  Error *err = NULL;
  CxlMemsimV2LineState state = CXL_MEMSIM_V2_STATE_I;
  CxlMemsimV2ClientStats stats;
  CxlMemsimV2LineState second_state = CXL_MEMSIM_V2_STATE_I;

  g_assert_true(cxl_memsim_v2_client_has_shared_range(client));
  g_assert_true(cxl_memsim_v2_shared_grant(client, TEST_SHARED_RANGE_A + 8,
                                           &peer, false, &state,
                                           TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmpint(state, ==, CXL_MEMSIM_V2_STATE_S);
  g_assert_cmphex(get_le64(peer.shared_page, 8), ==, 0);
  g_assert_true(cxl_memsim_v2_shared_grant(
      client,
      TEST_SHARED_RANGE_A +
          (CXL_MEMSIM_V2_RESIDENCY_PAGE_COUNT - 1) *
              CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE +
          8,
      &peer, false, &second_state, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmpint(second_state, ==, CXL_MEMSIM_V2_STATE_S);
  g_assert_true(cxl_memsim_v2_shared_grant(client, TEST_SHARED_RANGE_A + 8,
                                           &peer, true, &state, TEST_TIMEOUT_MS,
                                           &err));
  g_assert_null(err);
  g_assert_cmpint(state, ==, CXL_MEMSIM_V2_STATE_M);
  put_le64(peer.shared_page, 8, TEST_VALUE_A);
  put_le64(peer.shared_page, 16, TEST_VALUE_B);
  g_assert_cmphex(get_le64(peer.shared_page, 8), ==, TEST_VALUE_A);
  g_assert_true(wait_phase(&peer, 1));
  g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 2));
  g_assert_cmpint(g_atomic_int_get(&peer.shared_invalidations), ==, 1);
  g_assert_true(cxl_memsim_v2_shared_grant(
      client,
      TEST_SHARED_RANGE_A +
          (CXL_MEMSIM_V2_RESIDENCY_PAGE_COUNT - 1) *
              CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE +
          8,
      &peer, false, &second_state, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmpint(second_state, ==, CXL_MEMSIM_V2_STATE_E);
  g_assert_true(cxl_memsim_v2_shared_grant(client, TEST_SHARED_RANGE_A + 24,
                                           &peer, true, &state, TEST_TIMEOUT_MS,
                                           &err));
  g_assert_null(err);
  put_le64(peer.shared_page, 24, TEST_VALUE_A);
  g_assert_true(cxl_memsim_v2_shared_grant(
      client, TEST_SHARED_RANGE_A + CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE + 24,
      &peer, true, &state, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_cmpint(state, ==, CXL_MEMSIM_V2_STATE_M);
  g_assert_true(wait_phase(&peer, 3));
  cxl_memsim_v2_client_stats(client, &stats);
  g_assert_cmpuint(stats.gets, ==, 2);
  g_assert_cmpuint(stats.getm, ==, 1);
  g_assert_cmpuint(stats.upgrade, ==, 2);
  g_assert_cmpuint(stats.resident, ==, 1);
  g_assert_cmpuint(stats.puts, ==, 0);
  g_assert_cmpuint(stats.putm, ==, 0);
  g_assert_cmpuint(stats.fence, ==, 1);
  g_assert_cmpuint(stats.gets_ns, >, 0);
  g_assert_cmpuint(stats.getm_ns, >, 0);
  g_assert_cmpuint(stats.upgrade_ns, >, 0);
  g_assert_cmpuint(stats.resident_ns, >, 0);
  g_assert_cmpuint(stats.fence_ns, >, 0);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpint(g_atomic_int_get(&peer.shared_invalidations), ==, 2);
  g_assert_cmpuint(peer.gets, ==, 2);
  g_assert_cmpuint(peer.upgrades, ==, 2);
  g_assert_cmpuint(peer.resident, ==, 1);
  g_assert_cmpuint(peer.getm, ==, 1);
  g_assert_cmpuint(peer.putm, ==, 1);
  g_assert_cmpuint(peer.fences, ==, 2);
  g_assert_cmpuint(peer.snoop_acks, ==, 0);
  g_assert_true(peer.unregistered);
}

static void test_shared_residency_evicts_page_without_puts(void) {
  CachePeer peer = {
      .script = CACHE_PEER_SHARED_RESIDENCY_CAPACITY,
  };
  GThread *peer_thread;
  CxlMemsimV2Client *client = start_cache_client(
      &peer, CXL_MEMSIM_V2_SHARED_RANGE_SIZE, 1, &peer_thread);
  CxlMemsimV2ClientStats stats;
  Error *err = NULL;
  CxlMemsimV2LineState state;
  unsigned index;

  for (index = 0; index < 15; ++index) {
    g_assert_true(cxl_memsim_v2_shared_grant(
        client,
        TEST_SHARED_RANGE_A +
            index * (uint64_t)CXL_MEMSIM_V2_SHARED_RANGE_SIZE + 8,
        &peer, false, &state, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmpint(state, ==, CXL_MEMSIM_V2_STATE_S);
  }
  g_assert_true(cxl_memsim_v2_shared_grant(
      client,
      TEST_SHARED_RANGE_A +
          8 * (uint64_t)CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE + 8,
      &peer, false, &state, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_shared_grant(
      client,
      TEST_SHARED_RANGE_A +
          3 * (uint64_t)CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE + 8,
      &peer, false, &state, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
  g_assert_null(err);
  g_assert_true(wait_phase(&peer, 1));
  cxl_memsim_v2_client_stats(client, &stats);
  g_assert_cmpuint(stats.gets, ==, 15);
  g_assert_cmpuint(stats.resident, ==, 3);
  g_assert_cmpuint(stats.puts, ==, 0);

  finish_cache_test(&peer, peer_thread, client);
  g_assert_cmpuint(peer.gets, ==, 15);
  g_assert_cmpuint(peer.resident, ==, 3);
  g_assert_cmpuint(peer.puts, ==, 0);
  g_assert_true(peer.unregistered);
}

int main(int argc, char **argv) {
  module_call_init(MODULE_INIT_QOM);
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/cxl/type2/memsim-v2-cache/wb-retain",
                  test_wb_store_and_m_hit_do_not_putm_until_fence);
  g_test_add_func("/cxl/type2/memsim-v2-cache/cache-block-persist",
                  test_cache_block_writeback_reaches_persistence_fence);
  g_test_add_func("/cxl/type2/memsim-v2-cache/dirty-downgrade",
                  test_dirty_owner_snoop_downgrade_returns_full_line);
  g_test_add_func("/cxl/type2/memsim-v2-cache/exclusive-load",
                  test_exclusive_load_uses_getm);
  g_test_add_func("/cxl/type2/memsim-v2-cache/dirty-eviction",
                  test_dirty_lru_eviction_is_only_early_putm);
  g_test_add_func("/cxl/type2/memsim-v2-cache/upgrade-hits",
                  test_e_and_s_store_hits_use_explicit_upgrade);
  g_test_add_func("/cxl/type2/memsim-v2-cache/write-through",
                  test_write_through_policy_putm_after_store);
  g_test_add_func("/cxl/type2/memsim-v2-cache/free-flush-unregister",
                  test_free_flushes_dirty_data_then_unregisters);
  g_test_add_func("/cxl/type2/memsim-v2-cache/free-flush-failure",
                  test_free_flush_failure_does_not_unregister);
  g_test_add_func("/cxl/type2/memsim-v2-cache/free-fence-failure",
                  test_free_fence_failure_does_not_unregister);
  g_test_add_func("/cxl/type2/memsim-v2-cache/immediate-post-grant-snoop",
                  test_immediate_post_grant_snoop_observes_installed_line);
  g_test_add_func("/cxl/type2/memsim-v2-cache/disjoint-set-overlap",
                  test_disjoint_cache_sets_issue_concurrent_requests);
  g_test_add_func("/cxl/type2/memsim-v2-cache/pipelined-writeback",
                  test_cache_block_writebacks_are_pipelined_before_fence);
  g_test_add_func("/cxl/type2/memsim-v2-cache/shared-range",
                  test_shared_range_fence_releases_then_reacquires_grant);
  g_test_add_func("/cxl/type2/memsim-v2-cache/shared-residency-capacity",
                  test_shared_residency_evicts_page_without_puts);

  return g_test_run();
}
