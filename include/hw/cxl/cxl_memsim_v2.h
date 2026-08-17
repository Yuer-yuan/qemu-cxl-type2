/*
 * CXLMemSim protocol-v2 duplex endpoint client
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CXL_MEMSIM_V2_H
#define CXL_MEMSIM_V2_H

#include "qapi/error.h"

#define CXL_MEMSIM_V2_MAGIC UINT32_C(0x32565843)
#define CXL_MEMSIM_V2_VERSION 2
#define CXL_MEMSIM_V2_FRAME_SIZE 192
#define CXL_MEMSIM_V2_LINE_SIZE 64
/*
 * Direct mappings use one ownership grant for a 64 KiB range.
 * TCG still installs 4 KiB translations, so a conflict revokes the whole
 * grant before any writable subpage can survive the snoop ACK.
 */
#define CXL_MEMSIM_V2_SHARED_RANGE_SIZE 65536
#define CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE 4096
#define CXL_MEMSIM_V2_RESIDENCY_PAGE_COUNT                                     \
  (CXL_MEMSIM_V2_SHARED_RANGE_SIZE / CXL_MEMSIM_V2_RESIDENCY_PAGE_SIZE)
#define CXL_MEMSIM_V2_RESIDENCY_FULL_MASK UINT64_C(0xffff)
#define CXL_MEMSIM_V2_MAX_ENDPOINTS 64
#define CXL_MEMSIM_V2_SERVER_ENDPOINT UINT16_C(0xffff)
#define CXL_MEMSIM_V2_HOST_ENDPOINT 0
#define CXL_MEMSIM_V2_DEVICE_ENDPOINT 1

#define CXL_MEMSIM_V2_CAP_MODEL_SNOOP (UINT64_C(1) << 0)
#define CXL_MEMSIM_V2_CAP_NATIVE_FLUSH (UINT64_C(1) << 1)
#define CXL_MEMSIM_V2_CAP_SHARED_RANGE (UINT64_C(1) << 2)

typedef enum CxlMemsimV2Opcode {
  CXL_MEMSIM_V2_OP_REGISTER = 0x0001,
  CXL_MEMSIM_V2_OP_UNREGISTER = 0x0002,
  CXL_MEMSIM_V2_OP_GETS = 0x0003,
  CXL_MEMSIM_V2_OP_GETM = 0x0004,
  CXL_MEMSIM_V2_OP_UPGRADE = 0x0005,
  CXL_MEMSIM_V2_OP_PUTS = 0x0006,
  CXL_MEMSIM_V2_OP_PUTM = 0x0007,
  CXL_MEMSIM_V2_OP_ATOMIC_FAA = 0x0008,
  CXL_MEMSIM_V2_OP_ATOMIC_CAS = 0x0009,
  CXL_MEMSIM_V2_OP_FENCE = 0x000a,
  CXL_MEMSIM_V2_OP_SNOOP_ACK = 0x000b,
  CXL_MEMSIM_V2_OP_HEARTBEAT = 0x000c,
  /* value adds resident 4 KiB pages; expected releases them. */
  CXL_MEMSIM_V2_OP_RESIDENT = 0x000d,
  CXL_MEMSIM_V2_OP_RESPONSE = 0x8001,
  CXL_MEMSIM_V2_OP_SNP_INV = 0x8101,
  CXL_MEMSIM_V2_OP_SNP_DOWNGRADE = 0x8102,
  CXL_MEMSIM_V2_OP_SNP_DATA_INV = 0x8103,
  CXL_MEMSIM_V2_OP_SNP_DATA_DOWNGRADE = 0x8104,
  CXL_MEMSIM_V2_OP_HOST_FENCE = 0x8105,
} CxlMemsimV2Opcode;

typedef enum CxlMemsimV2Status {
  CXL_MEMSIM_V2_STATUS_OK = 0,
  CXL_MEMSIM_V2_STATUS_BAD_PROTOCOL = 1,
  CXL_MEMSIM_V2_STATUS_PROTOCOL_REQUIRED = 2,
  CXL_MEMSIM_V2_STATUS_DUPLICATE_HOST = 3,
  CXL_MEMSIM_V2_STATUS_STALE_SESSION = 4,
  CXL_MEMSIM_V2_STATUS_STALE_EPOCH = 5,
  CXL_MEMSIM_V2_STATUS_STALE_REQUEST = 6,
  CXL_MEMSIM_V2_STATUS_INVALID_STATE = 7,
  CXL_MEMSIM_V2_STATUS_COHERENCE_TIMEOUT = 8,
  CXL_MEMSIM_V2_STATUS_HOST_FENCED = 9,
  CXL_MEMSIM_V2_STATUS_NO_CAPABILITY = 10,
  CXL_MEMSIM_V2_STATUS_IO_ERROR = 11,
} CxlMemsimV2Status;

typedef enum CxlMemsimV2AckStrength {
  CXL_MEMSIM_V2_ACK_NONE = 0,
  CXL_MEMSIM_V2_ACK_MODEL = 1,
  CXL_MEMSIM_V2_ACK_NATIVE = 2,
} CxlMemsimV2AckStrength;

typedef enum CxlMemsimV2LineState {
  CXL_MEMSIM_V2_STATE_I = 0,
  CXL_MEMSIM_V2_STATE_S = 1,
  CXL_MEMSIM_V2_STATE_E = 2,
  CXL_MEMSIM_V2_STATE_M = 3,
} CxlMemsimV2LineState;

typedef struct CxlMemsimV2Frame {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t flags;
  uint16_t status;
  uint8_t ack_strength;
  uint8_t state;
  uint16_t src_host;
  uint16_t dst_host;
  uint16_t payload_len;
  uint16_t reserved0;
  uint64_t request_id;
  uint64_t snoop_id;
  uint64_t session_id;
  uint64_t addr;
  uint64_t epoch;
  uint64_t capabilities;
  uint64_t expected;
  uint64_t value;
  uint64_t old_value;
  uint32_t size;
  uint32_t reserved1;
  uint8_t data[CXL_MEMSIM_V2_LINE_SIZE];
  uint8_t reserved[24];
} CxlMemsimV2Frame;

typedef struct CxlMemsimV2Client CxlMemsimV2Client;

typedef struct CxlMemsimV2ClientStats {
  uint64_t gets;
  uint64_t getm;
  uint64_t upgrade;
  uint64_t puts;
  uint64_t putm;
  uint64_t fence;
  uint64_t resident;
  uint64_t gets_ns;
  uint64_t getm_ns;
  uint64_t upgrade_ns;
  uint64_t puts_ns;
  uint64_t putm_ns;
  uint64_t fence_ns;
  uint64_t resident_ns;
} CxlMemsimV2ClientStats;

typedef enum CxlMemsimV2WritePolicy {
  CXL_MEMSIM_V2_WRITE_BACK,
  CXL_MEMSIM_V2_WRITE_THROUGH,
} CxlMemsimV2WritePolicy;

typedef enum CxlMemsimV2Path {
  CXL_MEMSIM_V2_PATH_CFMWS_HOST,
  CXL_MEMSIM_V2_PATH_BAR2_DEVICE,
} CxlMemsimV2Path;

typedef struct CxlMemsimV2EndpointPair {
  CxlMemsimV2Client *host;
  CxlMemsimV2Client *device;
} CxlMemsimV2EndpointPair;

/* The client fills the ACK envelope. The handler sets status/state/data. */
typedef bool (*CxlMemsimV2SnoopHandler)(void *opaque,
                                        const CxlMemsimV2Frame *snoop,
                                        CxlMemsimV2Frame *ack, Error **errp);

/* Accesses a Type-3 memdev mapping after a shared-range grant. */
typedef bool (*CxlMemsimV2SharedAccessHandler)(void *opaque, void *mapping,
                                               uint64_t address, uint8_t *data,
                                               unsigned size, bool write,
                                               Error **errp);

/* Revokes a direct shared-range mapping before its protocol grant changes. */
typedef bool (*CxlMemsimV2SharedInvalidateHandler)(
    void *opaque, void *mapping, uint64_t address, unsigned size,
    CxlMemsimV2LineState old_state, CxlMemsimV2LineState new_state,
    Error **errp);

/* Services execution-context work while a direct-grant request is waiting. */
typedef void (*CxlMemsimV2WaitServiceHandler)(void *opaque);

void cxl_memsim_v2_frame_init(CxlMemsimV2Frame *frame,
                              CxlMemsimV2Opcode opcode);
void cxl_memsim_v2_encode_frame(const CxlMemsimV2Frame *frame,
                                uint8_t bytes[CXL_MEMSIM_V2_FRAME_SIZE]);
bool cxl_memsim_v2_decode_frame(const uint8_t bytes[CXL_MEMSIM_V2_FRAME_SIZE],
                                CxlMemsimV2Frame *frame, Error **errp);

CxlMemsimV2Client *
cxl_memsim_v2_client_new(uint16_t endpoint,
                         CxlMemsimV2SnoopHandler snoop_handler,
                         void *snoop_opaque);
bool cxl_memsim_v2_client_set_write_policy(CxlMemsimV2Client *client,
                                           CxlMemsimV2WritePolicy policy,
                                           Error **errp);
bool cxl_memsim_v2_client_set_shared_access(
    CxlMemsimV2Client *client, CxlMemsimV2SharedAccessHandler handler,
    void *opaque, Error **errp);
bool cxl_memsim_v2_client_set_shared_invalidate(
    CxlMemsimV2Client *client, CxlMemsimV2SharedInvalidateHandler handler,
    void *opaque, Error **errp);
bool cxl_memsim_v2_client_set_wait_service(
    CxlMemsimV2Client *client, CxlMemsimV2WaitServiceHandler handler,
    void *opaque, Error **errp);

/* Takes ownership of fd on both success and failure. */
bool cxl_memsim_v2_client_start_fd(CxlMemsimV2Client *client, int fd,
                                   uint32_t cache_capacity, uint16_t cache_ways,
                                   int timeout_ms, Error **errp);
bool cxl_memsim_v2_client_connect(CxlMemsimV2Client *client, const char *host,
                                  uint16_t port, uint32_t cache_capacity,
                                  uint16_t cache_ways, int timeout_ms,
                                  Error **errp);
void cxl_memsim_v2_client_free(CxlMemsimV2Client *client);

/*
 * Completes a correlated request through the sole progress reader. The caller
 * supplies opcode-specific fields; the client supplies endpoint/session/ID.
 */
bool cxl_memsim_v2_client_transact(CxlMemsimV2Client *client,
                                   CxlMemsimV2Frame *request,
                                   CxlMemsimV2Frame *response, int timeout_ms,
                                   Error **errp);

/* Accesses use the bounded cache geometry negotiated during registration. */
bool cxl_memsim_v2_load(CxlMemsimV2Client *client, uint64_t address,
                        unsigned size, uint64_t *value, int timeout_ms,
                        Error **errp);
bool cxl_memsim_v2_load_exclusive(CxlMemsimV2Client *client, uint64_t address,
                                  unsigned size, uint64_t *value,
                                  int timeout_ms, Error **errp);
bool cxl_memsim_v2_store(CxlMemsimV2Client *client, uint64_t address,
                         unsigned size, uint64_t value, int timeout_ms,
                         Error **errp);
bool cxl_memsim_v2_shared_load(CxlMemsimV2Client *client, uint64_t address,
                               unsigned size, uint64_t *value, void *mapping,
                               int timeout_ms, Error **errp);
bool cxl_memsim_v2_shared_load_exclusive(CxlMemsimV2Client *client,
                                         uint64_t address, unsigned size,
                                         uint64_t *value, void *mapping,
                                         int timeout_ms, Error **errp);
bool cxl_memsim_v2_shared_store(CxlMemsimV2Client *client, uint64_t address,
                                unsigned size, uint64_t value, void *mapping,
                                int timeout_ms, Error **errp);
/* Acquires and pins one shared-range grant without copying its payload. */
bool cxl_memsim_v2_shared_grant(CxlMemsimV2Client *client, uint64_t address,
                                void *mapping, bool write,
                                CxlMemsimV2LineState *state, int timeout_ms,
                                Error **errp);
bool cxl_memsim_v2_fetch_add(CxlMemsimV2Client *client, uint64_t address,
                             uint64_t addend, uint64_t *old_value,
                             uint64_t *new_value, int timeout_ms, Error **errp);
bool cxl_memsim_v2_compare_exchange(CxlMemsimV2Client *client, uint64_t address,
                                    uint64_t expected, uint64_t desired,
                                    uint64_t *old_value, uint64_t *new_value,
                                    int timeout_ms, Error **errp);
bool cxl_memsim_v2_fence(CxlMemsimV2Client *client, int timeout_ms,
                         Error **errp);
/* Write back one cached line. If @persist is true, follow the writeback with
 * a protocol FENCE so the device backend reaches its persistence domain. */
bool cxl_memsim_v2_cache_block(CxlMemsimV2Client *client, uint64_t address,
                               bool persist, int timeout_ms, Error **errp);

uint16_t cxl_memsim_v2_client_endpoint(CxlMemsimV2Client *client);
uint64_t cxl_memsim_v2_client_session(CxlMemsimV2Client *client);
unsigned cxl_memsim_v2_client_progress_starts(CxlMemsimV2Client *client);
bool cxl_memsim_v2_client_has_shared_range(CxlMemsimV2Client *client);
void cxl_memsim_v2_client_stats(CxlMemsimV2Client *client,
                                CxlMemsimV2ClientStats *stats);
CxlMemsimV2Client *cxl_memsim_v2_path_client(CxlMemsimV2EndpointPair *endpoints,
                                             CxlMemsimV2Path path);

#endif /* CXL_MEMSIM_V2_H */
