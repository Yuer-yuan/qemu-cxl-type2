/*
 * SiFive U synthetic CXL firmware table tests
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/nvram/fw_cfg.h"
#include "hw/pci/pci_bridge.h"
#include "libqtest.h"
#include "qemu/bswap.h"
#include "qemu/units.h"
#include "qobject/qdict.h"
#include "qobject/qlist.h"
#include "standard-headers/linux/pci_regs.h"

#define SIFIVE_U_FW_CFG_DATA     0x10100000ULL
#define SIFIVE_U_FW_CFG_SELECTOR (SIFIVE_U_FW_CFG_DATA + 8)
#define SIFIVE_U_CXL_FMW_BASE    0x1000000000ULL
#define SIFIVE_U_CXL_FMW_SIZE    (64ULL * GiB)
#define SIFIVE_U_CXL_MMIO64_BASE 0x400000000ULL
#define SIFIVE_U_CXL_MMIO64_SIZE (4ULL * GiB)
#define SIFIVE_U_CXL_CHBS_BASE   0x800000000ULL
#define SIFIVE_U_CXL_CHBS_SIZE   (64 * KiB)
#define SIFIVE_U_PCIE_ECAM_BASE  0x30000000ULL
#define SIFIVE_U_RHCT_NODE_ARRAY_OFFSET 56

typedef struct QEMU_PACKED TestAcpiHeader {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    char asl_compiler_id[4];
    uint32_t asl_compiler_revision;
} TestAcpiHeader;

static void fw_cfg_select(QTestState *qts, uint16_t key)
{
    qtest_writew(qts, SIFIVE_U_FW_CFG_SELECTOR, cpu_to_be16(key));
}

static void fw_cfg_read(QTestState *qts, uint16_t key, void *buf, size_t len)
{
    uint8_t *p = buf;
    size_t i;

    fw_cfg_select(qts, key);
    for (i = 0; i < len; i++) {
        p[i] = qtest_readb(qts, SIFIVE_U_FW_CFG_DATA);
    }
}

static GByteArray *fw_cfg_file(QTestState *qts, const char *name)
{
    g_autofree uint8_t *directory = NULL;
    FWCfgFile *entry;
    uint32_t count;
    size_t directory_size;
    uint32_t i;

    fw_cfg_read(qts, FW_CFG_FILE_DIR, &count, sizeof(count));
    count = be32_to_cpu(count);
    directory_size = sizeof(count) + count * sizeof(FWCfgFile);
    directory = g_malloc(directory_size);
    fw_cfg_read(qts, FW_CFG_FILE_DIR, directory, directory_size);

    entry = (FWCfgFile *)(directory + sizeof(count));
    for (i = 0; i < count; i++, entry++) {
        if (!strcmp(entry->name, name)) {
            uint32_t size = be32_to_cpu(entry->size);
            uint16_t selector = be16_to_cpu(entry->select);
            GByteArray *data = g_byte_array_sized_new(size);

            g_byte_array_set_size(data, size);
            fw_cfg_read(qts, selector, data->data, data->len);
            return data;
        }
    }

    return NULL;
}

static bool buffer_contains(const uint8_t *buf, size_t len,
                            const char *needle)
{
    size_t needle_len = strlen(needle);
    size_t i;

    for (i = 0; i + needle_len <= len; i++) {
        if (!memcmp(buf + i, needle, needle_len)) {
            return true;
        }
    }
    return false;
}

static bool buffer_contains_cxl_mmio64(const uint8_t *buf, size_t len)
{
    uint8_t descriptor[46] = {
        0x8a, 0x2b, 0x00, 0x00, 0x0c, 0x07,
    };
    size_t i;

    stq_le_p(descriptor + 6, 0);
    stq_le_p(descriptor + 14, SIFIVE_U_CXL_MMIO64_BASE);
    stq_le_p(descriptor + 22,
             SIFIVE_U_CXL_MMIO64_BASE + SIFIVE_U_CXL_MMIO64_SIZE - 1);
    stq_le_p(descriptor + 30, 0);
    stq_le_p(descriptor + 38, SIFIVE_U_CXL_MMIO64_SIZE);

    for (i = 0; i + sizeof(descriptor) <= len; i++) {
        if (!memcmp(buf + i, descriptor, sizeof(descriptor))) {
            return true;
        }
    }
    return false;
}

static bool device_has_property(QTestState *qts, const char *type,
                                const char *property)
{
    QDict *response;
    QList *properties;
    QListEntry *entry;
    bool found = false;

    response = qtest_qmp(qts,
                         "{'execute': 'device-list-properties',"
                         " 'arguments': {'typename': %s}}", type);
    properties = qdict_get_qlist(response, "return");
    QLIST_FOREACH_ENTRY(properties, entry) {
        QDict *description = qobject_to(QDict, qlist_entry_obj(entry));

        if (!strcmp(qdict_get_str(description, "name"), property)) {
            found = true;
            break;
        }
    }
    qobject_unref(response);
    return found;
}

static void test_type3_coherence_v2_properties(void)
{
    static const char * const expected[] = {
        "coherence-v2",
        "x-gpf",
        "x-gpf-state-file",
        "cxlmemsim-addr",
        "cxlmemsim-port",
        "coherence-v2-host-id",
        "coherence-v2-cache-capacity",
        "coherence-v2-cache-ways",
        "coherence-v2-timeout-ms",
        "coherence-v2-write-through",
        "coherence-v2-read-exclusive",
        "x-256b-flit",
        "hdm-db",
    };
    QTestState *qts = qtest_init("-machine none");
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(expected); i++) {
        g_assert_true(device_has_property(qts, "cxl-type3", expected[i]));
    }
    g_assert_true(device_has_property(qts, "cxl-rp", "x-256b-flit"));
    qtest_quit(qts);
}

static void assert_cedt(const uint8_t *table, size_t length)
{
    const uint8_t *entry = table + sizeof(TestAcpiHeader);
    const uint8_t *end = table + length;
    bool found_chbs = false;
    bool found_cfmws = false;

    while (entry + 4 <= end) {
        uint16_t entry_length = lduw_le_p(entry + 2);

        g_assert_cmpuint(entry_length, >=, 4);
        g_assert_true(entry + entry_length <= end);
        if (entry[0] == 0) {
            found_chbs = true;
        } else if (entry[0] == 1) {
            g_assert_cmpuint(entry_length, >=, 36);
            if (ldq_le_p(entry + 8) == SIFIVE_U_CXL_FMW_BASE &&
                ldq_le_p(entry + 16) == SIFIVE_U_CXL_FMW_SIZE) {
                g_assert_cmphex(lduw_le_p(entry + 32), ==, 0x29);
                found_cfmws = true;
            }
        }
        entry += entry_length;
    }

    g_assert_true(found_chbs);
    g_assert_true(found_cfmws);
}

static void assert_madt(const uint8_t *table, size_t length)
{
    const uint8_t *entry = table + sizeof(TestAcpiHeader) + 8;
    const uint8_t *end = table + length;
    unsigned int rintc = 0;

    while (entry + 2 <= end) {
        uint8_t entry_length = entry[1];

        g_assert_cmpuint(entry_length, >=, 2);
        g_assert_true(entry + entry_length <= end);
        if (entry[0] == 0x18) {
            uint64_t hart_id;

            g_assert_cmpuint(entry_length, ==, 36);
            hart_id = ldq_le_p(entry + 8);
            g_assert_cmpuint(hart_id, ==, rintc + 1);
            g_assert_cmpuint(ldl_le_p(entry + 16), ==, hart_id);
            g_assert_cmpuint(ldl_le_p(entry + 20), ==, 2 * hart_id);
            rintc++;
        }
        entry += entry_length;
    }

    g_assert_cmpuint(rintc, ==, 4);
}

static void assert_rhct(const uint8_t *table, size_t length)
{
    const uint8_t *end = table + length;
    const uint8_t *node;
    uint32_t isa_offset = 0;
    uint32_t cmo_offset = 0;
    uint32_t node_count;
    unsigned int hart_nodes = 0;

    g_assert_cmpuint(length, >=, SIFIVE_U_RHCT_NODE_ARRAY_OFFSET);
    node_count = ldl_le_p(table + sizeof(TestAcpiHeader) + 12);
    g_assert_cmpuint(node_count, ==, 6);
    node = table + ldl_le_p(table + sizeof(TestAcpiHeader) + 16);

    for (uint32_t i = 0; i < node_count; i++) {
        uint16_t type;
        uint16_t node_length;

        g_assert_true(node + 4 <= end);
        type = lduw_le_p(node);
        node_length = lduw_le_p(node + 2);
        g_assert_cmpuint(node_length, >=, 4);
        g_assert_true(node + node_length <= end);
        if (type == 0) {
            isa_offset = node - table;
        } else if (type == 1) {
            g_assert_cmpuint(node_length, ==, 10);
            g_assert_cmpuint(lduw_le_p(node + 4), ==, 1);
            g_assert_cmpuint(node[6], ==, 0);
            g_assert_cmpuint(node[7], ==, 6);
            g_assert_cmpuint(node[8], ==, 0);
            g_assert_cmpuint(node[9], ==, 6);
            cmo_offset = node - table;
        } else if (type == 0xffff) {
            g_assert_cmpuint(node_length, ==, 20);
            g_assert_cmpuint(lduw_le_p(node + 6), ==, 2);
            g_assert_cmpuint(ldl_le_p(node + 8), ==, hart_nodes + 1);
            g_assert_cmpuint(ldl_le_p(node + 12), ==, isa_offset);
            g_assert_cmpuint(ldl_le_p(node + 16), ==, cmo_offset);
            hart_nodes++;
        }
        node += node_length;
    }

    g_assert_cmpuint(isa_offset, !=, 0);
    g_assert_cmpuint(cmo_offset, !=, 0);
    g_assert_cmpuint(hart_nodes, ==, 4);
}

static void assert_acpi_tables(GByteArray *tables)
{
    const uint8_t *cedt = NULL;
    const uint8_t *madt_table = NULL;
    const uint8_t *rhct_table = NULL;
    size_t cedt_length = 0;
    size_t madt_length = 0;
    size_t rhct_length = 0;
    size_t offset = 0;
    unsigned int dsdt = 0;
    unsigned int fadt = 0;
    unsigned int madt = 0;
    unsigned int rhct = 0;
    unsigned int mcfg = 0;
    unsigned int cedt_count = 0;

    while (offset + sizeof(TestAcpiHeader) <= tables->len) {
        const TestAcpiHeader *header =
            (const TestAcpiHeader *)(tables->data + offset);
        uint32_t length = le32_to_cpu(header->length);

        if (!memcmp(header->signature, "\0\0\0\0", 4)) {
            break;
        }
        g_assert_cmpuint(length, >=, sizeof(*header));
        g_assert_cmpuint(offset + length, <=, tables->len);

        if (!memcmp(header->signature, "DSDT", 4)) {
            dsdt++;
        } else if (!memcmp(header->signature, "FACP", 4)) {
            fadt++;
        } else if (!memcmp(header->signature, "APIC", 4)) {
            madt++;
            madt_table = tables->data + offset;
            madt_length = length;
        } else if (!memcmp(header->signature, "RHCT", 4)) {
            rhct++;
            rhct_table = tables->data + offset;
            rhct_length = length;
        } else if (!memcmp(header->signature, "MCFG", 4)) {
            mcfg++;
        } else if (!memcmp(header->signature, "CEDT", 4)) {
            cedt_count++;
            cedt = tables->data + offset;
            cedt_length = length;
        }
        offset += length;
    }

    g_assert_cmpuint(dsdt, ==, 1);
    g_assert_cmpuint(fadt, ==, 1);
    g_assert_cmpuint(madt, ==, 1);
    g_assert_cmpuint(rhct, ==, 1);
    g_assert_cmpuint(mcfg, ==, 1);
    g_assert_cmpuint(cedt_count, ==, 1);
    g_assert_true(buffer_contains(tables->data, tables->len, "ACPI0016"));
    g_assert_true(buffer_contains(tables->data, tables->len, "ACPI0017"));
    g_assert_true(buffer_contains(tables->data, tables->len, "CXLM"));
    g_assert_true(buffer_contains(tables->data, tables->len, "_DEP"));
    g_assert_true(buffer_contains_cxl_mmio64(tables->data, tables->len));
    assert_cedt(cedt, cedt_length);
    assert_madt(madt_table, madt_length);
    assert_rhct(rhct_table, rhct_length);
}

static void assert_cxl_pxb_firmware_cap(QTestState *qts)
{
    uint64_t config = SIFIVE_U_PCIE_ECAM_BASE + (1 << 15);
    uint8_t offset = qtest_readb(qts, config + PCI_CAPABILITY_LIST);
    unsigned int ttl = 48;

    while (offset && ttl--) {
        uint8_t id = qtest_readb(qts, config + offset);

        if (id == PCI_CAP_ID_VNDR &&
            qtest_readb(qts, config + offset + 2) ==
                QEMU_CXL_PXB_CAP_LENGTH &&
            qtest_readb(qts, config + offset +
                         QEMU_CXL_PXB_CAP_TYPE_OFF) ==
                QEMU_CXL_PXB_CAP_TYPE &&
            qtest_readb(qts, config + offset +
                         QEMU_CXL_PXB_CAP_SIG_OFF) == 'C' &&
            qtest_readb(qts, config + offset +
                         QEMU_CXL_PXB_CAP_SIG_OFF + 1) == 'X' &&
            qtest_readb(qts, config + offset +
                         QEMU_CXL_PXB_CAP_SIG_OFF + 2) == 'L') {
            g_assert_cmpuint(qtest_readb(qts, config + offset +
                                         QEMU_CXL_PXB_CAP_BUS_OFF),
                             ==, 64);
            g_assert_cmpuint(qtest_readb(qts, config + offset +
                                         QEMU_CXL_PXB_CAP_VERSION_OFF),
                             ==, 1);
            g_assert_cmpuint(qtest_readb(qts, config + offset +
                                         QEMU_CXL_PXB_CAP_FMW_COUNT_OFF),
                             ==, 1);
            g_assert_cmphex(qtest_readq(qts, config + offset +
                                        QEMU_CXL_PXB_CAP_CHBS_BASE_OFF),
                            ==, SIFIVE_U_CXL_CHBS_BASE);
            g_assert_cmphex(qtest_readq(qts, config + offset +
                                        QEMU_CXL_PXB_CAP_CHBS_SIZE_OFF),
                            ==, SIFIVE_U_CXL_CHBS_SIZE);
            g_assert_cmphex(qtest_readq(qts, config + offset +
                                        QEMU_CXL_PXB_CAP_FMW_BASE_OFF(0)),
                            ==, SIFIVE_U_CXL_FMW_BASE);
            g_assert_cmphex(qtest_readq(qts, config + offset +
                                        QEMU_CXL_PXB_CAP_FMW_SIZE_OFF(0)),
                            ==, SIFIVE_U_CXL_FMW_SIZE);
            return;
        }
        offset = qtest_readb(qts, config + offset + 1);
    }

    g_assert_not_reached();
}

static void test_firmware_files(void)
{
    g_autoptr(GByteArray) tables = NULL;
    g_autoptr(GByteArray) loader = NULL;
    g_autoptr(GByteArray) rsdp = NULL;
    QTestState *qts;

    qts = qtest_init(
        "-machine sifive_u,cxl=on -cpu veyron-v1 -smp 5 "
        "-machine cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=64G,"
        "cxl-fmw.0.restrictions=0x29 "
        "-object memory-backend-ram,id=t3mem,size=256M,share=on "
        "-object memory-backend-ram,id=t3lsa,size=2M,share=on "
        "-device pxb-cxl,bus=pcie.0,bus_nr=64,id=cxl.1 "
        "-device cxl-rp,bus=cxl.1,port=0,id=rp-t2,chassis=0,slot=0,"
        "x-256b-flit=on "
        "-device cxl-type2,bus=rp-t2,gpu-mode=0,mem-size=256M,"
        "cache-size=64M,id=t2 "
        "-device cxl-rp,bus=cxl.1,port=1,id=rp-t3,chassis=0,slot=1,"
        "x-256b-flit=on "
        "-device cxl-type3,bus=rp-t3,volatile-memdev=t3mem,"
        "lsa=t3lsa,id=t3,x-256b-flit=on");

    tables = fw_cfg_file(qts, "etc/acpi/tables");
    loader = fw_cfg_file(qts, "etc/table-loader");
    rsdp = fw_cfg_file(qts, "etc/acpi/rsdp");

    g_assert_nonnull(tables);
    g_assert_cmpuint(tables->len, >, 0);
    g_assert_nonnull(loader);
    g_assert_cmpuint(loader->len, >, 0);
    g_assert_nonnull(rsdp);
    g_assert_cmpuint(rsdp->len, >, 0);
    assert_acpi_tables(tables);
    assert_cxl_pxb_firmware_cap(qts);

    qtest_quit(qts);
}

static unsigned find_gpf_dvsec(QTestState *qts, uint64_t config, unsigned id)
{
    unsigned offset = 0x100;
    unsigned ttl = 256;

    while (offset && ttl--) {
        uint32_t header = qtest_readl(qts, config + offset);

        if ((header & 0xffff) == 0x23 &&
            qtest_readw(qts, config + offset + 4) == 0x1e98 &&
            qtest_readw(qts, config + offset + 8) == id) {
            g_assert_cmphex(qtest_readl(qts, config + offset + 4) >> 20,
                            ==, 0x10);
            return offset;
        }
        offset = header >> 20;
    }
    g_assert_not_reached();
}

static void test_gpf_dvsec_attributes(void)
{
    QTestState *qts = qtest_init(
        "-machine sifive_u,cxl=on -cpu veyron-v1 -smp 5 -S "
        "-object memory-backend-ram,id=mem,size=256M "
        "-object memory-backend-ram,id=lsa,size=2M "
        "-device pxb-cxl,bus=pcie.0,bus_nr=64,id=cxl.1 "
        "-device cxl-rp,bus=cxl.1,port=0,id=rp,chassis=0,slot=0 "
        "-device cxl-type3,bus=rp,persistent-memdev=mem,lsa=lsa,id=t3");
    uint64_t port = SIFIVE_U_PCIE_ECAM_BASE + (64ULL << 20);
    uint64_t device = SIFIVE_U_PCIE_ECAM_BASE + (65ULL << 20);
    unsigned offset;
    uint16_t duration;
    uint32_t power;
    QDict *response;

    qtest_writeb(qts, port + PCI_PRIMARY_BUS, 64);
    qtest_writeb(qts, port + PCI_SECONDARY_BUS, 65);
    qtest_writeb(qts, port + PCI_SUBORDINATE_BUS, 65);
    offset = find_gpf_dvsec(qts, port, 4);
    g_assert_cmphex(qtest_readw(qts, port + offset + 12), ==, 0x070f);
    g_assert_cmphex(qtest_readw(qts, port + offset + 14), ==, 0x060a);
    qtest_writel(qts, port + offset + 12, 0xffffffff);
    g_assert_cmphex(qtest_readl(qts, port + offset + 12), ==, 0x0f0f0f0f);
    qtest_writew(qts, port + offset + 12, 0x0702);
    qtest_writew(qts, port + offset + 14, 0x0702);
    g_assert_cmphex(qtest_readl(qts, port + offset + 12), ==, 0x07020702);

    offset = find_gpf_dvsec(qts, device, 5);
    duration = qtest_readw(qts, device + offset + 10);
    power = qtest_readl(qts, device + offset + 12);
    g_assert_cmphex(duration, ==, 0x0603);
    g_assert_cmphex(power, ==, 0x33);
    qtest_writew(qts, device + offset + 10, ~duration);
    qtest_writel(qts, device + offset + 12, ~power);
    g_assert_cmphex(qtest_readw(qts, device + offset + 10), ==, duration);
    g_assert_cmphex(qtest_readl(qts, device + offset + 12), ==, power);
    qtest_writeb(qts, device + offset + 10, 0xff);
    qtest_writeb(qts, device + offset + 11, 0xff);
    g_assert_cmphex(qtest_readw(qts, device + offset + 10), ==, duration);
    response = qtest_qmp(qts, "{'execute':'x-cxl-gpf',"
                         "'arguments':{'path':'/machine/peripheral/t3','phase':1}}");
    g_assert_true(qdict_haskey(response, "error"));
    qobject_unref(response);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/riscv/sifive-u/cxl/gpf-dvsec", test_gpf_dvsec_attributes);
    qtest_add_func("/riscv/sifive-u/cxl/type3-coherence-v2-properties",
                   test_type3_coherence_v2_properties);
    qtest_add_func("/riscv/sifive-u/cxl/firmware-files",
                   test_firmware_files);
    return g_test_run();
}
