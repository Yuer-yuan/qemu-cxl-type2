#include "qemu/osdep.h"

#include "hw/cxl/cxl_memsim_v2.h"
#include "qapi/error.h"
#include "qemu/module.h"

#include <poll.h>
#include <netinet/tcp.h>

#define TEST_TIMEOUT_MS 2000
#define NO_FRAME_MS 100
#define TEST_LINE_A UINT64_C(0x1000)
#define TEST_LINE_B UINT64_C(0x2000)
#define TEST_LINE_C (TEST_LINE_A + CXL_MEMSIM_V2_LINE_SIZE)
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
    CACHE_PEER_IMMEDIATE_LOAD_SNOOP,
    CACHE_PEER_CLEAN_EVICTION_SNOOP_RACE,
    CACHE_PEER_UPGRADE_SNOOP_RACE,
    CACHE_PEER_EXCLUSIVE_LOAD,
    CACHE_PEER_CACHE_BLOCK,
    CACHE_PEER_RELEASE_DOWNGRADE,
    CACHE_PEER_RELEASE_DOWNGRADE_STALE,
    CACHE_PEER_RELEASE_CLEAN_DOWNGRADE,
    CACHE_PEER_RELEASE_DOWNGRADE_INVALIDATE,
    CACHE_PEER_RELEASE_UNPROVED_ERROR,
    CACHE_PEER_RELEASE_DOWNGRADE_IO_ERROR,
    CACHE_PEER_FENCE_WORKLIST,
    CACHE_PEER_FENCE_WORKLIST_SNOOP,
    CACHE_PEER_TCP_STREAM,
    CACHE_PEER_GPF,
    CACHE_PEER_GPF_FAILURE,
    CACHE_PEER_GPF_TIMEOUT,
    CACHE_PEER_GPF_NO_CAP,
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
    unsigned puts;
    unsigned putm;
    unsigned fences;
    unsigned snoop_acks;
    bool immediate_load_reacquired;
    uint64_t written_a;
    uint64_t written_b;
    uint16_t teardown_order[3];
    unsigned teardown_count;
    bool unregistered;
    bool immediate_snoop_acked;
    bool tcp_nodelay;
} CachePeer;

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

static void init_wire_frame(uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE], uint16_t opcode) {
    memset(frame, 0, CXL_MEMSIM_V2_FRAME_SIZE);
    put_le32(frame, 0, CXL_MEMSIM_V2_MAGIC);
    put_le16(frame, 4, CXL_MEMSIM_V2_VERSION);
    put_le16(frame, 6, opcode);
}

static bool send_registration_response(CachePeer *peer, const uint8_t *request) {
    uint8_t response[CXL_MEMSIM_V2_FRAME_SIZE];

    init_wire_frame(response, CXL_MEMSIM_V2_OP_RESPONSE);
    response[14] = CXL_MEMSIM_V2_ACK_MODEL;
    put_le16(response, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
    put_le16(response, 18, get_le16(request, 16));
    put_le64(response, 40, TEST_SESSION);
    put_le64(response, 64, peer->script == CACHE_PEER_GPF_NO_CAP ?
             CXL_MEMSIM_V2_CAP_MODEL_SNOOP : get_le64(request, 64));
    put_le64(response, 72, get_le64(request, 72));
    put_le64(response, 80, get_le64(request, 80));
    put_le64(response, 88, 1);
    put_le32(response, 96, CXL_MEMSIM_V2_LINE_SIZE);
    return write_all(peer->fd, response, sizeof(response));
}

static bool send_response(CachePeer *peer, const uint8_t *request, uint8_t state, uint64_t epoch, const uint8_t *line,
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
    if (line) {
        put_le16(response, 20, CXL_MEMSIM_V2_LINE_SIZE);
        memcpy(response + 104, line, CXL_MEMSIM_V2_LINE_SIZE);
    }
    return write_all(peer->fd, response, sizeof(response));
}

static bool send_error_response(CachePeer *peer, const uint8_t *request, uint16_t status) {
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

static bool expect_frame(CachePeer *peer, uint16_t opcode, uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
    if (!read_all_timeout(peer->fd, frame, CXL_MEMSIM_V2_FRAME_SIZE)) {
        g_test_message("timed out waiting for opcode 0x%x", opcode);
        peer->error_code = EPROTO;
        return false;
    }
    if (get_le16(frame, 6) == CXL_MEMSIM_V2_OP_HEARTBEAT &&
        opcode != CXL_MEMSIM_V2_OP_HEARTBEAT) {
        return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0) &&
               expect_frame(peer, opcode, frame);
    }
    if (get_le32(frame, 0) != CXL_MEMSIM_V2_MAGIC || get_le16(frame, 6) != opcode ||
        get_le16(frame, 16) != CXL_MEMSIM_V2_DEVICE_ENDPOINT || get_le64(frame, 40) != TEST_SESSION) {
        g_test_message("expected opcode 0x%x, got 0x%x host=%u session=%" PRIu64, opcode, get_le16(frame, 6),
                       get_le16(frame, 16), get_le64(frame, 40));
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
    int64_t deadline = g_get_monotonic_time() + TEST_TIMEOUT_MS * G_TIME_SPAN_MILLISECOND;
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

static bool expect_register(CachePeer *peer, uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
    if (!read_all_timeout(peer->fd, frame, CXL_MEMSIM_V2_FRAME_SIZE) ||
        get_le16(frame, 6) != CXL_MEMSIM_V2_OP_REGISTER || get_le16(frame, 16) != CXL_MEMSIM_V2_DEVICE_ENDPOINT ||
        !send_registration_response(peer, frame)) {
        peer->error_code = EPROTO;
        return false;
    }
    return true;
}

static bool expect_fence(CachePeer *peer, uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
    return expect_frame(peer, CXL_MEMSIM_V2_OP_FENCE, frame) &&
           send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0);
}

static bool expect_unregister(CachePeer *peer, uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_UNREGISTER, frame) ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0)) {
        return false;
    }
    peer->unregistered = true;
    return true;
}

static bool expect_clean_teardown(CachePeer *peer, uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE]) {
    return expect_fence(peer, frame) && expect_unregister(peer, frame);
}

static bool expect_putm(CachePeer *peer, uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE], uint64_t address, uint64_t value,
                        uint64_t epoch) {
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) || get_le64(frame, 48) != address ||
        get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE || get_le64(frame, 104) != value) {
        g_test_message("PUTM expected addr=%" PRIx64 " value=%" PRIx64 ", got addr=%" PRIx64
                       " length=%u value=%" PRIx64,
                       address, value, get_le64(frame, 48), get_le16(frame, 20), get_le64(frame, 104));
        peer->error_code = EPROTO;
        return false;
    }
    if (address == TEST_LINE_A) {
        peer->written_a = get_le64(frame, 104);
    } else if (address == TEST_LINE_B) {
        peer->written_b = get_le64(frame, 104);
    }
    return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, epoch, NULL, 0);
}

static bool expect_puts(CachePeer *peer,
                        uint8_t frame[CXL_MEMSIM_V2_FRAME_SIZE],
                        uint64_t address, uint64_t epoch)
{
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTS, frame) ||
        get_le64(frame, 48) != address || get_le16(frame, 20)) {
        peer->error_code = EPROTO;
        return false;
    }
    return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, epoch, NULL, 0);
}

static bool run_wb_retain_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) || !no_frame_available(peer)) {
        return false;
    }
    set_phase(peer, 1);
    return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_B, 2) && expect_fence(peer, frame) &&
           expect_clean_teardown(peer, frame);
}

static bool run_exclusive_load_script(CachePeer *peer, uint8_t *frame)
{
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

static bool run_cache_block_script(CachePeer *peer, uint8_t *frame)
{
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
        get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
        !no_frame_available(peer)) {
        return false;
    }
    set_phase(peer, 1);
    if (!expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2)) {
        return false;
    }
    set_phase(peer, 2);
    return expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
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
    if (!wait_phase(peer, 2) || !send_dirty_downgrade(peer) || !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
        get_le64(frame, 32) != 77 || get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
        frame[14] != CXL_MEMSIM_V2_ACK_MODEL || frame[15] != CXL_MEMSIM_V2_STATE_S ||
        get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE || get_le64(frame, 104) != TEST_VALUE_A) {
        peer->error_code = EPROTO;
        return false;
    }
    set_phase(peer, 3);
    return expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_dirty_eviction_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) || !no_frame_available(peer)) {
        return false;
    }
    set_phase(peer, 1);
    if (!expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2) || !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
        get_le64(frame, 48) != TEST_LINE_B || !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
        !no_frame_available(peer)) {
        return false;
    }
    set_phase(peer, 2);
    return expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 2) && expect_fence(peer, frame) &&
           expect_clean_teardown(peer, frame);
}

static bool run_upgrade_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line_a[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t line_b[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    put_le64(line_a, 0, 1);
    put_le64(line_b, 0, 2);
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 1, line_a, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        frame[15] != CXL_MEMSIM_V2_STATE_E || get_le64(frame, 56) != 1 ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 2, NULL, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) || get_le64(frame, 48) != TEST_LINE_B ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_S, 5, line_b, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) || get_le64(frame, 48) != TEST_LINE_B ||
        frame[15] != CXL_MEMSIM_V2_STATE_S || get_le64(frame, 56) != 5 ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 6, NULL, 0) || !no_frame_available(peer)) {
        return false;
    }
    set_phase(peer, 1);
    return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 3) &&
           expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 7) && expect_clean_teardown(peer, frame);
}

static bool run_write_through_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
        !expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2)) {
        return false;
    }
    set_phase(peer, 1);
    return expect_clean_teardown(peer, frame);
}

static bool record_teardown_frame(CachePeer *peer, const uint8_t *frame, uint16_t opcode) {
    if (peer->teardown_count >= G_N_ELEMENTS(peer->teardown_order)) {
        peer->error_code = EOVERFLOW;
        return false;
    }
    peer->teardown_order[peer->teardown_count++] = opcode;
    return true;
}

static bool run_free_flush_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
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

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
        return false;
    }
    set_phase(peer, 1);
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE || get_le64(frame, 104) != TEST_VALUE_A ||
        !record_teardown_frame(peer, frame, CXL_MEMSIM_V2_OP_PUTM)) {
        return false;
    }
    peer->written_a = get_le64(frame, 104);
    return send_error_response(peer, frame, CXL_MEMSIM_V2_STATUS_IO_ERROR);
}

static bool run_free_fence_failure_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
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
    uint64_t snooped_value;

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
    if (!write_all(peer->fd, snoop, sizeof(snoop)) || !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
        get_le64(frame, 32) != 91 || get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
        frame[15] != CXL_MEMSIM_V2_STATE_I ||
        get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE) {
        peer->error_code = EPROTO;
        return false;
    }
    peer->immediate_snoop_acked = true;
    snooped_value = get_le64(frame, 104);

    if (snooped_value == TEST_VALUE_B) {
        /* The store linearized before the snoop and needs no retry. */
        set_phase(peer, 1);
        return expect_clean_teardown(peer, frame);
    }
    if (snooped_value != TEST_VALUE_A) {
        peer->error_code = EPROTO;
        return false;
    }

    memset(line, 0, sizeof(line));
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 3, line, 0)) {
        return false;
    }
    set_phase(peer, 1);
    return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_B, 4) &&
           expect_clean_teardown(peer, frame);
}

static bool run_immediate_load_snoop_script(CachePeer *peer, uint8_t *frame)
{
    uint8_t first_line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t second_line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];

    put_le64(first_line, 0, TEST_VALUE_A);
    put_le64(second_line, 0, TEST_VALUE_B);
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 1,
                       first_line, 0)) {
        return false;
    }
    init_wire_frame(snoop, CXL_MEMSIM_V2_OP_SNP_INV);
    put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
    put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
    put_le64(snoop, 32, 94);
    put_le64(snoop, 40, TEST_SESSION);
    put_le64(snoop, 48, TEST_LINE_A);
    put_le64(snoop, 56, 2);
    if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
        get_le64(frame, 32) != 94 ||
        get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
        frame[15] != CXL_MEMSIM_V2_STATE_I) {
        peer->error_code = EPROTO;
        return false;
    }
    set_phase(peer, 1);
    if (!read_all_timeout(peer->fd, frame, CXL_MEMSIM_V2_FRAME_SIZE) ||
        get_le32(frame, 0) != CXL_MEMSIM_V2_MAGIC ||
        get_le16(frame, 16) != CXL_MEMSIM_V2_DEVICE_ENDPOINT ||
        get_le64(frame, 40) != TEST_SESSION) {
        peer->error_code = EPROTO;
        return false;
    }
    if (get_le16(frame, 6) == CXL_MEMSIM_V2_OP_GETS) {
        if (get_le64(frame, 48) != TEST_LINE_A ||
            !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 3,
                           second_line, 0)) {
            peer->error_code = EPROTO;
            return false;
        }
        peer->gets++;
        peer->immediate_load_reacquired = true;
        return expect_clean_teardown(peer, frame);
    }
    if (get_le16(frame, 6) == CXL_MEMSIM_V2_OP_FENCE) {
        peer->fences++;
        return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0,
                             NULL, 0) &&
               expect_unregister(peer, frame);
    }
    peer->error_code = EPROTO;
    return false;
}

static bool run_clean_eviction_snoop_race_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line_a[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t line_b[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t puts_request[CXL_MEMSIM_V2_FRAME_SIZE];
    uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];

    put_le64(line_a, 0, TEST_VALUE_A);
    put_le64(line_b, 0, TEST_VALUE_B);
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 1, line_a, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_PUTS, frame) || get_le64(frame, 48) != TEST_LINE_A) {
        return false;
    }
    memcpy(puts_request, frame, sizeof(puts_request));

    init_wire_frame(snoop, CXL_MEMSIM_V2_OP_SNP_INV);
    put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
    put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
    put_le64(snoop, 32, 92);
    put_le64(snoop, 40, TEST_SESSION);
    put_le64(snoop, 48, TEST_LINE_A);
    put_le64(snoop, 56, 2);
    if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
        get_le64(frame, 32) != 92 || get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
        frame[15] != CXL_MEMSIM_V2_STATE_I ||
        !send_error_response(peer, puts_request, CXL_MEMSIM_V2_STATUS_INVALID_STATE) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) || get_le64(frame, 48) != TEST_LINE_B ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 3, line_b, 0)) {
        return false;
    }
    set_phase(peer, 1);
    return expect_clean_teardown(peer, frame);
}

static bool run_upgrade_snoop_race_script(CachePeer *peer, uint8_t *frame) {
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t upgrade_request[CXL_MEMSIM_V2_FRAME_SIZE];
    uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];

    put_le64(line, 0, TEST_VALUE_A);
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 1, line, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_UPGRADE, frame) || get_le64(frame, 48) != TEST_LINE_A) {
        return false;
    }
    memcpy(upgrade_request, frame, sizeof(upgrade_request));

    init_wire_frame(snoop, CXL_MEMSIM_V2_OP_SNP_INV);
    put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
    put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
    put_le64(snoop, 32, 93);
    put_le64(snoop, 40, TEST_SESSION);
    put_le64(snoop, 48, TEST_LINE_A);
    put_le64(snoop, 56, 2);
    if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
        get_le64(frame, 32) != 93 || get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
        frame[15] != CXL_MEMSIM_V2_STATE_I ||
        !send_error_response(peer, upgrade_request, CXL_MEMSIM_V2_STATUS_STALE_EPOCH) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) || get_le64(frame, 48) != TEST_LINE_A ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 3, line, 0)) {
        return false;
    }
    set_phase(peer, 1);
    return expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_B, 4) && expect_clean_teardown(peer, frame);
}

/* Deterministic wire ordering reproduces the IO500 PUTM/downgrade race. */
static bool run_release_downgrade_script(CachePeer *peer, uint8_t *frame)
{
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t release[CXL_MEMSIM_V2_FRAME_SIZE];
    uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];
    const bool clean = peer->script == CACHE_PEER_RELEASE_CLEAN_DOWNGRADE;
    uint16_t status = (clean || peer->script == CACHE_PEER_RELEASE_DOWNGRADE_STALE) ?
        CXL_MEMSIM_V2_STATUS_STALE_EPOCH : CXL_MEMSIM_V2_STATUS_INVALID_STATE;

    if (!expect_frame(peer, clean ? CXL_MEMSIM_V2_OP_GETS : CXL_MEMSIM_V2_OP_GETM, frame) ||
        !send_response(peer, frame, clean ? CXL_MEMSIM_V2_STATE_E : CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
        !expect_frame(peer, clean ? CXL_MEMSIM_V2_OP_PUTS : CXL_MEMSIM_V2_OP_PUTM, frame) ||
        get_le64(frame, 48) != TEST_LINE_A || get_le64(frame, 56) != 1 ||
        frame[15] != (clean ? CXL_MEMSIM_V2_STATE_E : CXL_MEMSIM_V2_STATE_M) ||
        get_le16(frame, 20) != (clean ? 0 : CXL_MEMSIM_V2_LINE_SIZE) ||
        (!clean && get_le64(frame, 104) != TEST_VALUE_A)) {
        return false;
    }
    memcpy(release, frame, sizeof(release));
    if (peer->script == CACHE_PEER_RELEASE_UNPROVED_ERROR) {
        /* No newer snoop: the first operation MUST fail and retain M. */
        return send_error_response(peer, release, status) &&
               expect_putm(peer, frame, TEST_LINE_A, TEST_VALUE_A, 2) &&
               expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
    }

    init_wire_frame(snoop, clean ? CXL_MEMSIM_V2_OP_SNP_DOWNGRADE : CXL_MEMSIM_V2_OP_SNP_DATA_DOWNGRADE);
    put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
    put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
    put_le64(snoop, 32, 94);
    put_le64(snoop, 40, TEST_SESSION);
    put_le64(snoop, 48, TEST_LINE_A);
    put_le64(snoop, 56, 2);
    if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
        get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
        frame[15] != CXL_MEMSIM_V2_STATE_S || get_le64(frame, 56) != 2 ||
        get_le16(frame, 20) != (clean ? 0 : CXL_MEMSIM_V2_LINE_SIZE) ||
        (!clean && memcmp(frame + 104, release + 104, CXL_MEMSIM_V2_LINE_SIZE) != 0)) {
        return false;
    }
    peer->written_a = get_le64(frame, 104);
    if (peer->script == CACHE_PEER_RELEASE_DOWNGRADE_IO_ERROR) {
        status = CXL_MEMSIM_V2_STATUS_IO_ERROR;
    }
    if (!send_error_response(peer, release, status) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_PUTS, frame) ||
        get_le64(frame, 48) != TEST_LINE_A || get_le64(frame, 56) != 2 ||
        frame[15] != CXL_MEMSIM_V2_STATE_S || get_le16(frame, 20) != 0) {
        return false;
    }
    memcpy(release, frame, sizeof(release));
    if (peer->script == CACHE_PEER_RELEASE_DOWNGRADE_INVALIDATE) {
        put_le16(snoop, 6, CXL_MEMSIM_V2_OP_SNP_INV);
        put_le64(snoop, 32, 95);
        put_le64(snoop, 56, 3);
        if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
            !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
            get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
            frame[15] != CXL_MEMSIM_V2_STATE_I ||
            !send_error_response(peer, release, CXL_MEMSIM_V2_STATUS_INVALID_STATE)) {
            return false;
        }
    } else if (!send_response(peer, release, CXL_MEMSIM_V2_STATE_I, 3, NULL, 0)) {
        return false;
    }
    return expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_fence_worklist_script(CachePeer *peer, uint8_t *frame)
{
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};
    uint8_t release[CXL_MEMSIM_V2_FRAME_SIZE];
    uint8_t snoop[CXL_MEMSIM_V2_FRAME_SIZE];
    const uint64_t addresses[] = { TEST_LINE_A, TEST_LINE_B, TEST_LINE_C };

    for (size_t i = 0; i < G_N_ELEMENTS(addresses); i++) {
        if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
            get_le64(frame, 48) != addresses[i] ||
            !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
            return false;
        }
    }
    /* Remove the middle slot with CBO, then reacquire the same cache slot. */
    if (!expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 2) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
        get_le64(frame, 48) != TEST_LINE_B ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 3, line, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_PUTM, frame) ||
        get_le64(frame, 48) != TEST_LINE_A ||
        get_le64(frame, 104) != TEST_VALUE_A) {
        return false;
    }
    memcpy(release, frame, sizeof(release));
    if (peer->script == CACHE_PEER_FENCE_WORKLIST_SNOOP) {
        /* Remove the next M holder while the first release is in flight. */
        init_wire_frame(snoop, CXL_MEMSIM_V2_OP_SNP_DATA_INV);
        put_le16(snoop, 16, CXL_MEMSIM_V2_SERVER_ENDPOINT);
        put_le16(snoop, 18, CXL_MEMSIM_V2_DEVICE_ENDPOINT);
        put_le64(snoop, 32, 96);
        put_le64(snoop, 40, TEST_SESSION);
        put_le64(snoop, 48, TEST_LINE_C);
        put_le64(snoop, 56, 2);
        if (!write_all(peer->fd, snoop, sizeof(snoop)) ||
            !expect_frame(peer, CXL_MEMSIM_V2_OP_SNOOP_ACK, frame) ||
            get_le16(frame, 12) != CXL_MEMSIM_V2_STATUS_OK ||
            frame[15] != CXL_MEMSIM_V2_STATE_I ||
            get_le16(frame, 20) != CXL_MEMSIM_V2_LINE_SIZE ||
            get_le64(frame, 104) != TEST_VALUE_A) {
            return false;
        }
    }
    if (!send_response(peer, release, CXL_MEMSIM_V2_STATE_I, 2, NULL, 0)) {
        return false;
    }
    if (peer->script != CACHE_PEER_FENCE_WORKLIST_SNOOP &&
        !expect_putm(peer, frame, TEST_LINE_C, TEST_VALUE_A, 2)) {
        return false;
    }
    return expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 4) &&
           expect_fence(peer, frame) && expect_fence(peer, frame) &&
           expect_clean_teardown(peer, frame);
}

static bool run_tcp_stream_script(CachePeer *peer, uint8_t *frame)
{
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    for (unsigned i = 0; i < 1024; i++) {
        if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
            get_le64(frame, 48) != TEST_LINE_A + i * CXL_MEMSIM_V2_LINE_SIZE ||
            !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0)) {
            return false;
        }
    }
    for (unsigned i = 0; i < 1024; i++) {
        if (!expect_putm(peer, frame, TEST_LINE_A + i * CXL_MEMSIM_V2_LINE_SIZE, TEST_VALUE_A, 2)) {
            return false;
        }
    }
    return expect_fence(peer, frame) && expect_clean_teardown(peer, frame);
}

static bool run_gpf_script(CachePeer *peer, uint8_t *frame)
{
    uint8_t line[CXL_MEMSIM_V2_LINE_SIZE] = {0};

    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GETS, frame) ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_E, 1, line, 0) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
        !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1, line, 0) ||
        !expect_putm(peer, frame, TEST_LINE_B, TEST_VALUE_B, 2) ||
        !expect_frame(peer, CXL_MEMSIM_V2_OP_GPF_PHASE1, frame)) {
        return false;
    }
    if (peer->script == CACHE_PEER_GPF_FAILURE) {
        if (!send_error_response(peer, frame, CXL_MEMSIM_V2_STATUS_IO_ERROR) ||
            !expect_frame(peer, CXL_MEMSIM_V2_OP_GPF_PHASE1, frame)) {
            return false;
        }
    }
    if (!send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0)) {
        return false;
    }
    if (peer->script != CACHE_PEER_GPF_FAILURE) {
        if (!expect_puts(peer, frame, TEST_LINE_A, 2) ||
            !expect_frame(peer, CXL_MEMSIM_V2_OP_GETM, frame) ||
            get_le64(frame, 48) != TEST_LINE_C ||
            !send_response(peer, frame, CXL_MEMSIM_V2_STATE_M, 1,
                           line, 0) ||
            !expect_putm(peer, frame, TEST_LINE_C, TEST_VALUE_A, 2)) {
            return false;
        }
    }
    if (!expect_frame(peer, CXL_MEMSIM_V2_OP_GPF_PHASE2, frame)) {
        return false;
    }
    if (peer->script == CACHE_PEER_GPF_FAILURE) {
        if (!send_error_response(peer, frame, CXL_MEMSIM_V2_STATUS_IO_ERROR) ||
            !expect_frame(peer, CXL_MEMSIM_V2_OP_GPF_PHASE2, frame)) {
            return false;
        }
    }
    if (peer->script == CACHE_PEER_GPF_TIMEOUT) {
        uint64_t original_id = get_le64(frame, 24);

        /* Drop both responses; the client must retry the same request ID. */
        return expect_frame(peer, CXL_MEMSIM_V2_OP_GPF_PHASE2, frame) &&
               get_le64(frame, 24) == original_id;
    }
    return send_response(peer, frame, CXL_MEMSIM_V2_STATE_I, 0, NULL, 0);
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
    case CACHE_PEER_IMMEDIATE_LOAD_SNOOP:
        success = run_immediate_load_snoop_script(peer, frame);
        break;
    case CACHE_PEER_CLEAN_EVICTION_SNOOP_RACE:
        success = run_clean_eviction_snoop_race_script(peer, frame);
        break;
    case CACHE_PEER_UPGRADE_SNOOP_RACE:
        success = run_upgrade_snoop_race_script(peer, frame);
        break;
    case CACHE_PEER_EXCLUSIVE_LOAD:
        success = run_exclusive_load_script(peer, frame);
        break;
    case CACHE_PEER_CACHE_BLOCK:
        success = run_cache_block_script(peer, frame);
        break;
    case CACHE_PEER_RELEASE_DOWNGRADE:
    case CACHE_PEER_RELEASE_DOWNGRADE_STALE:
    case CACHE_PEER_RELEASE_CLEAN_DOWNGRADE:
    case CACHE_PEER_RELEASE_DOWNGRADE_INVALIDATE:
    case CACHE_PEER_RELEASE_UNPROVED_ERROR:
    case CACHE_PEER_RELEASE_DOWNGRADE_IO_ERROR:
        success = run_release_downgrade_script(peer, frame);
        break;
    case CACHE_PEER_FENCE_WORKLIST:
    case CACHE_PEER_FENCE_WORKLIST_SNOOP:
        success = run_fence_worklist_script(peer, frame);
        break;
    case CACHE_PEER_TCP_STREAM:
        success = run_tcp_stream_script(peer, frame);
        break;
    case CACHE_PEER_GPF:
    case CACHE_PEER_GPF_FAILURE:
    case CACHE_PEER_GPF_TIMEOUT:
        success = run_gpf_script(peer, frame);
        break;
    case CACHE_PEER_GPF_NO_CAP:
        success = true;
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

static CxlMemsimV2Client *start_cache_client(CachePeer *peer, uint32_t cache_capacity, uint16_t cache_ways,
                                             GThread **peer_thread) {
    int sockets[2];
    CxlMemsimV2Client *client;
    Error *err = NULL;

    g_mutex_init(&peer->phase_lock);
    g_cond_init(&peer->phase_changed);
    if (peer->script == CACHE_PEER_TCP_STREAM) {
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        };
        socklen_t length = sizeof(address);
        int enabled = peer->tcp_nodelay;

        g_assert_cmpint(listener, >=, 0);
        g_assert_cmpint(bind(listener, (struct sockaddr *)&address, length), ==, 0);
        g_assert_cmpint(getsockname(listener, (struct sockaddr *)&address, &length), ==, 0);
        g_assert_cmpint(listen(listener, 1), ==, 0);
        sockets[0] = socket(AF_INET, SOCK_STREAM, 0);
        g_assert_cmpint(connect(sockets[0], (struct sockaddr *)&address, length), ==, 0);
        sockets[1] = accept(listener, NULL, NULL);
        close(listener);
        g_assert_cmpint(sockets[1], >=, 0);
        for (unsigned i = 0; i < 2; i++) {
            g_assert_cmpint(setsockopt(sockets[i], IPPROTO_TCP, TCP_NODELAY,
                                      &enabled, sizeof(enabled)), ==, 0);
        }
    } else {
        g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
    }
    peer->fd = sockets[1];
    *peer_thread = g_thread_new("memsim-v2-cache-peer", cache_peer_thread, peer);
    client = cxl_memsim_v2_client_new(CXL_MEMSIM_V2_DEVICE_ENDPOINT, NULL, NULL);
    g_assert_nonnull(client);
    if (peer->script == CACHE_PEER_GPF ||
        peer->script == CACHE_PEER_GPF_FAILURE ||
        peer->script == CACHE_PEER_GPF_TIMEOUT) {
        g_assert_true(cxl_memsim_v2_client_enable_gpf(client, &err));
        g_assert_null(err);
    }
    if (peer->script == CACHE_PEER_WRITE_THROUGH) {
        g_assert_true(cxl_memsim_v2_client_set_write_policy(client, CXL_MEMSIM_V2_WRITE_THROUGH, &err));
        g_assert_null(err);
    }
    g_assert_true(cxl_memsim_v2_client_start_fd(client, sockets[0], cache_capacity, cache_ways, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    return client;
}

static void finish_cache_test(CachePeer *peer, GThread *peer_thread, CxlMemsimV2Client *client) {
    cxl_memsim_v2_client_free(client);
    g_thread_join(peer_thread);
    g_assert_cmpint(peer->error_code, ==, 0);
    g_cond_clear(&peer->phase_changed);
    g_mutex_clear(&peer->phase_lock);
}

static void test_wb_store_and_m_hit_do_not_putm_until_fence(void) {
    CachePeer peer = {
        .script = CACHE_PEER_WB_RETAIN,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    bool fenced;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 1));
    fenced = cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err);
    if (!fenced && err) {
        g_test_message("fence failed: %s", error_get_pretty(err));
    }
    g_assert_true(fenced);
    g_assert_null(err);

    g_assert_cmpuint(cxl_memsim_v2_client_fence_cache_visits(client), ==, 1);

    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmpuint(peer.getm, ==, 1);
    g_assert_cmpuint(peer.putm, ==, 1);
    g_assert_cmphex(peer.written_a, ==, TEST_VALUE_B);
}

static void test_dirty_owner_snoop_downgrade_returns_full_line(void) {
    CachePeer peer = {
        .script = CACHE_PEER_DIRTY_DOWNGRADE,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    set_phase(&peer, 2);
    g_assert_true(wait_phase(&peer, 3));
    g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);

    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmpuint(peer.snoop_acks, ==, 1);
    g_assert_cmpuint(peer.putm, ==, 0);
}

static void test_exclusive_load_uses_getm(void)
{
    CachePeer peer = {
        .script = CACHE_PEER_EXCLUSIVE_LOAD,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(
        &peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    uint64_t value = 0;

    g_assert_true(cxl_memsim_v2_load_exclusive(
        client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
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
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    bool fenced;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 1));
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
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

static void test_cache_block_writes_back_exact_dirty_line(void)
{
    CachePeer peer = {
        .script = CACHE_PEER_CACHE_BLOCK,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(
        &peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(
        client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 1));
    g_assert_true(cxl_memsim_v2_cache_block(
        client, TEST_LINE_A + 7, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 2));
    g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);

    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmpuint(peer.getm, ==, 1);
    g_assert_cmpuint(peer.putm, ==, 1);
    g_assert_cmphex(peer.written_a, ==, TEST_VALUE_A);
}

static void test_e_and_s_store_hits_use_explicit_upgrade(void) {
    CachePeer peer = {
        .script = CACHE_PEER_UPGRADE_HITS,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(&peer, 2 * CXL_MEMSIM_V2_LINE_SIZE, 2, &peer_thread);
    Error *err = NULL;
    uint64_t value = 0;

    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmpuint(value, ==, 1);
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmphex(value, ==, TEST_VALUE_A);

    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_B, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmpuint(value, ==, 2);
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
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
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
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
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
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
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
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
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
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
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 1));
    finish_cache_test(&peer, peer_thread, client);
    g_assert_true(peer.immediate_snoop_acked);
    g_assert_true(peer.getm == 1 || peer.getm == 2);
}

static void test_load_reacquires_immediately_snooped_grant(void)
{
    CachePeer peer = {
        .script = CACHE_PEER_IMMEDIATE_LOAD_SNOOP,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(
        &peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    uint64_t value = 0;

    g_assert_true(cxl_memsim_v2_load(
        client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 1));

    finish_cache_test(&peer, peer_thread, client);
    if (peer.immediate_load_reacquired) {
        g_assert_cmphex(value, ==, TEST_VALUE_B);
        g_assert_cmpuint(peer.gets, ==, 2);
    } else {
        g_assert_cmphex(value, ==, TEST_VALUE_A);
        g_assert_cmpuint(peer.gets, ==, 1);
    }
    g_assert_cmpuint(peer.snoop_acks, ==, 1);
}

static void test_clean_eviction_racing_snoop_is_already_complete(void) {
    CachePeer peer = {
        .script = CACHE_PEER_CLEAN_EVICTION_SNOOP_RACE,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    uint64_t value = 0;

    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmphex(value, ==, TEST_VALUE_A);
    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_B, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmphex(value, ==, TEST_VALUE_B);
    g_assert_true(wait_phase(&peer, 1));

    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmpuint(peer.gets, ==, 2);
    g_assert_cmpuint(peer.puts, ==, 1);
    g_assert_cmpuint(peer.snoop_acks, ==, 1);
}

static void test_upgrade_racing_snoop_reacquires_line(void) {
    CachePeer peer = {
        .script = CACHE_PEER_UPGRADE_SNOOP_RACE,
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(&peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    uint64_t value = 0;

    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmphex(value, ==, TEST_VALUE_A);
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_true(wait_phase(&peer, 1));

    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmpuint(peer.gets, ==, 1);
    g_assert_cmpuint(peer.getm, ==, 1);
    g_assert_cmpuint(peer.upgrades, ==, 1);
    g_assert_cmpuint(peer.putm, ==, 1);
    g_assert_cmpuint(peer.snoop_acks, ==, 1);
}

static void test_release_downgrade(gconstpointer opaque)
{
    CachePeer peer = { .script = GPOINTER_TO_INT(opaque) };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(
        &peer, CXL_MEMSIM_V2_LINE_SIZE, 1, &peer_thread);
    Error *err = NULL;
    bool released;

    if (peer.script == CACHE_PEER_RELEASE_CLEAN_DOWNGRADE) {
        uint64_t value;
        g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value, TEST_TIMEOUT_MS, &err));
        g_assert_cmphex(value, ==, 0);
    } else {
        g_assert_true(cxl_memsim_v2_store(
            client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    }
    g_assert_null(err);
    released = cxl_memsim_v2_cache_block(client, TEST_LINE_A, TEST_TIMEOUT_MS, &err);
    if (peer.script == CACHE_PEER_RELEASE_UNPROVED_ERROR ||
        peer.script == CACHE_PEER_RELEASE_DOWNGRADE_IO_ERROR) {
        g_assert_false(released);
        g_assert_nonnull(err);
        error_free(err);
        err = NULL;
        released = cxl_memsim_v2_cache_block(client, TEST_LINE_A, TEST_TIMEOUT_MS, &err);
    }
    if (!released && err) {
        g_test_message("release failed: %s", error_get_pretty(err));
    }
    g_assert_true(released);
    g_assert_null(err);
    g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmphex(peer.written_a, ==,
        peer.script == CACHE_PEER_RELEASE_CLEAN_DOWNGRADE ? 0 : TEST_VALUE_A);
    g_assert_cmpuint(peer.puts, ==,
        peer.script == CACHE_PEER_RELEASE_UNPROVED_ERROR ? 0 :
        peer.script == CACHE_PEER_RELEASE_CLEAN_DOWNGRADE ? 2 : 1);
}

static void test_fence_worklist(gconstpointer opaque)
{
    CachePeer peer = { .script = GPOINTER_TO_INT(opaque) };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(
        &peer, 32 * 1024 * 1024, 4, &peer_thread);
    Error *err = NULL;
    uint64_t expected = peer.script == CACHE_PEER_FENCE_WORKLIST ? 3 : 2;

    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_A, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_C, 8, TEST_VALUE_A, TEST_TIMEOUT_MS, &err));
    g_assert_true(cxl_memsim_v2_cache_block(client, TEST_LINE_B, TEST_TIMEOUT_MS, &err));
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B, TEST_TIMEOUT_MS, &err));
    g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmpuint(cxl_memsim_v2_client_fence_cache_visits(client), ==, expected);
    g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_assert_cmpuint(cxl_memsim_v2_client_fence_cache_visits(client), ==, expected);
    finish_cache_test(&peer, peer_thread, client);
}

static void test_tcp_stream(gconstpointer opaque)
{
    CachePeer peer = {
        .script = CACHE_PEER_TCP_STREAM,
        .tcp_nodelay = GPOINTER_TO_INT(opaque),
    };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(
        &peer, 1024 * CXL_MEMSIM_V2_LINE_SIZE, 4, &peer_thread);
    Error *err = NULL;
    int64_t started = g_get_monotonic_time();

    for (unsigned i = 0; i < 1024; i++) {
        g_assert_true(cxl_memsim_v2_store(client,
            TEST_LINE_A + i * CXL_MEMSIM_V2_LINE_SIZE, 8, TEST_VALUE_A,
            TEST_TIMEOUT_MS, &err));
        g_assert_null(err);
    }
    int64_t stored = g_get_monotonic_time();
    g_assert_true(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    g_test_message("TCP_STREAM nodelay=%u lines=1024 store_us=%" PRId64 " fence_us=%" PRId64,
                   peer.tcp_nodelay, stored - started, g_get_monotonic_time() - stored);
    finish_cache_test(&peer, peer_thread, client);
}

static void assert_gpf_frozen(CxlMemsimV2Client *client)
{
    Error *err = NULL;
    uint64_t old_value, new_value;

    /* Includes a clean cache hit and a dirty-line address. */
    g_assert_false(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &old_value,
                                     TEST_TIMEOUT_MS, &err));
    g_assert_nonnull(err);
    g_clear_pointer(&err, error_free);
    g_assert_false(cxl_memsim_v2_store(client, TEST_LINE_B, 8, 0,
                                      TEST_TIMEOUT_MS, &err));
    g_assert_nonnull(err);
    g_clear_pointer(&err, error_free);
    g_assert_false(cxl_memsim_v2_fetch_add(client, TEST_LINE_B, 1,
                                          &old_value, &new_value,
                                          TEST_TIMEOUT_MS, &err));
    g_assert_nonnull(err);
    g_clear_pointer(&err, error_free);
    g_assert_false(cxl_memsim_v2_fence(client, TEST_TIMEOUT_MS, &err));
    g_assert_nonnull(err);
    error_free(err);
}

static void test_gpf(gconstpointer opaque)
{
    CachePeer peer = { .script = GPOINTER_TO_INT(opaque) };
    GThread *peer_thread;
    CxlMemsimV2Client *client = start_cache_client(&peer, 256, 4, &peer_thread);
    Error *err = NULL;
    uint64_t value;

    g_assert_false(cxl_memsim_v2_gpf(client, 2, TEST_TIMEOUT_MS,
                                     2 * TEST_TIMEOUT_MS, &err));
    g_assert_nonnull(err);
    g_clear_pointer(&err, error_free);
    g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value,
                                    TEST_TIMEOUT_MS, &err));
    g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_B, 8, TEST_VALUE_B,
                                     TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    if (peer.script == CACHE_PEER_GPF_FAILURE) {
        g_assert_false(cxl_memsim_v2_gpf(client, 1, TEST_TIMEOUT_MS,
                                         2 * TEST_TIMEOUT_MS, &err));
        g_assert_nonnull(err);
        g_clear_pointer(&err, error_free);
        assert_gpf_frozen(client);
    }
    g_assert_true(cxl_memsim_v2_gpf(client, 1, TEST_TIMEOUT_MS,
                                    2 * TEST_TIMEOUT_MS, &err));
    g_assert_null(err);
    if (peer.script == CACHE_PEER_GPF_FAILURE) {
        assert_gpf_frozen(client);
    } else {
        g_assert_true(cxl_memsim_v2_load(client, TEST_LINE_A, 8, &value,
                                        TEST_TIMEOUT_MS, &err));
        g_assert_true(cxl_memsim_v2_store(client, TEST_LINE_C, 8,
                                         TEST_VALUE_A, TEST_TIMEOUT_MS,
                                         &err));
        g_assert_null(err);
    }
    if (peer.script == CACHE_PEER_GPF_FAILURE) {
        g_assert_false(cxl_memsim_v2_gpf(client, 2, TEST_TIMEOUT_MS,
                                         2 * TEST_TIMEOUT_MS, &err));
        g_assert_nonnull(err);
        g_clear_pointer(&err, error_free);
        assert_gpf_frozen(client);
    }
    if (peer.script == CACHE_PEER_GPF_TIMEOUT) {
        g_assert_false(cxl_memsim_v2_gpf(client, 2, 50, 100, &err));
        g_assert_nonnull(err);
        g_assert_nonnull(strstr(error_get_pretty(err), "timed out"));
        g_clear_pointer(&err, error_free);
    } else {
        g_assert_true(cxl_memsim_v2_gpf(client, 2, TEST_TIMEOUT_MS,
                                        2 * TEST_TIMEOUT_MS, &err));
        g_assert_null(err);
    }
    assert_gpf_frozen(client);
    finish_cache_test(&peer, peer_thread, client);
    g_assert_cmpuint(peer.putm, ==,
                     peer.script == CACHE_PEER_GPF_FAILURE ? 1 : 2);
    g_assert_cmpuint(peer.puts, ==,
                     peer.script == CACHE_PEER_GPF_FAILURE ? 0 : 1);
    g_assert_cmpuint(peer.fences, ==, 0);
    g_assert_false(peer.unregistered);
}

static void test_gpf_capability_required(void)
{
    CachePeer peer = { .script = CACHE_PEER_GPF_NO_CAP };
    CxlMemsimV2Client *client;
    GThread *thread;
    Error *err = NULL;
    int sockets[2];

    g_mutex_init(&peer.phase_lock);
    g_cond_init(&peer.phase_changed);
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
    peer.fd = sockets[1];
    thread = g_thread_new("gpf-no-cap", cache_peer_thread, &peer);
    client = cxl_memsim_v2_client_new(CXL_MEMSIM_V2_DEVICE_ENDPOINT,
                                     NULL, NULL);
    g_assert_true(cxl_memsim_v2_client_enable_gpf(client, &err));
    g_assert_false(cxl_memsim_v2_client_start_fd(client, sockets[0], 256, 4,
                                               TEST_TIMEOUT_MS, &err));
    g_assert_nonnull(strstr(error_get_pretty(err), "GPF capability"));
    error_free(err);
    finish_cache_test(&peer, thread, client);
}

int main(int argc, char **argv) {
    module_call_init(MODULE_INIT_QOM);
    g_test_init(&argc, &argv, NULL);

    g_test_add_data_func("/cxl/memsim-v2-cache/gpf",
                        GINT_TO_POINTER(CACHE_PEER_GPF), test_gpf);
    g_test_add_data_func("/cxl/memsim-v2-cache/gpf-failure",
                        GINT_TO_POINTER(CACHE_PEER_GPF_FAILURE), test_gpf);
    g_test_add_data_func("/cxl/memsim-v2-cache/gpf-timeout",
                        GINT_TO_POINTER(CACHE_PEER_GPF_TIMEOUT), test_gpf);
    g_test_add_func("/cxl/memsim-v2-cache/gpf-capability-required",
                   test_gpf_capability_required);

    g_test_add_func("/cxl/type2/memsim-v2-cache/wb-retain", test_wb_store_and_m_hit_do_not_putm_until_fence);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/fence-worklist",
        GINT_TO_POINTER(CACHE_PEER_FENCE_WORKLIST), test_fence_worklist);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/fence-worklist-snoop",
        GINT_TO_POINTER(CACHE_PEER_FENCE_WORKLIST_SNOOP), test_fence_worklist);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/tcp-stream-nagle",
        GINT_TO_POINTER(0), test_tcp_stream);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/tcp-stream-nodelay",
        GINT_TO_POINTER(1), test_tcp_stream);
    g_test_add_func("/cxl/type2/memsim-v2-cache/dirty-downgrade", test_dirty_owner_snoop_downgrade_returns_full_line);
    g_test_add_func("/cxl/type2/memsim-v2-cache/exclusive-load", test_exclusive_load_uses_getm);
    g_test_add_func("/cxl/type2/memsim-v2-cache/dirty-eviction", test_dirty_lru_eviction_is_only_early_putm);
    g_test_add_func("/cxl/type2/memsim-v2-cache/cache-block", test_cache_block_writes_back_exact_dirty_line);
    g_test_add_func("/cxl/type2/memsim-v2-cache/upgrade-hits", test_e_and_s_store_hits_use_explicit_upgrade);
    g_test_add_func("/cxl/type2/memsim-v2-cache/write-through", test_write_through_policy_putm_after_store);
    g_test_add_func("/cxl/type2/memsim-v2-cache/free-flush-unregister", test_free_flushes_dirty_data_then_unregisters);
    g_test_add_func("/cxl/type2/memsim-v2-cache/free-flush-failure", test_free_flush_failure_does_not_unregister);
    g_test_add_func("/cxl/type2/memsim-v2-cache/free-fence-failure", test_free_fence_failure_does_not_unregister);
    g_test_add_func("/cxl/type2/memsim-v2-cache/immediate-post-grant-snoop",
                    test_immediate_post_grant_snoop_observes_installed_line);
    g_test_add_func("/cxl/type2/memsim-v2-cache/load-grant-snoop-retry",
                    test_load_reacquires_immediately_snooped_grant);
    g_test_add_func("/cxl/type2/memsim-v2-cache/clean-eviction-snoop-race",
                    test_clean_eviction_racing_snoop_is_already_complete);
    g_test_add_func("/cxl/type2/memsim-v2-cache/upgrade-snoop-race",
                    test_upgrade_racing_snoop_reacquires_line);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/release-downgrade",
        GINT_TO_POINTER(CACHE_PEER_RELEASE_DOWNGRADE), test_release_downgrade);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/release-downgrade-stale",
        GINT_TO_POINTER(CACHE_PEER_RELEASE_DOWNGRADE_STALE), test_release_downgrade);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/release-clean-downgrade",
        GINT_TO_POINTER(CACHE_PEER_RELEASE_CLEAN_DOWNGRADE), test_release_downgrade);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/release-downgrade-invalidate",
        GINT_TO_POINTER(CACHE_PEER_RELEASE_DOWNGRADE_INVALIDATE), test_release_downgrade);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/release-unproved-error",
        GINT_TO_POINTER(CACHE_PEER_RELEASE_UNPROVED_ERROR), test_release_downgrade);
    g_test_add_data_func("/cxl/type2/memsim-v2-cache/release-downgrade-io-error",
        GINT_TO_POINTER(CACHE_PEER_RELEASE_DOWNGRADE_IO_ERROR), test_release_downgrade);

    return g_test_run();
}
