/*
 * CXL 2.0 Root Port Implementation
 *
 * Copyright(C) 2020 Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/range.h"
#include "hw/pci/pci_bridge.h"
#include "hw/pci-bridge/cxl_root_port.h"
#include "hw/pci/pcie_port.h"
#include "hw/pci/msi.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/sysbus.h"
#include "qapi/error.h"
#include "hw/cxl/cxl.h"

#define CXL_ROOT_PORT_DID 0x7075

#define CXL_RP_MSI_OFFSET               0x60
#define CXL_RP_MSI_SUPPORTED_FLAGS      PCI_MSI_FLAGS_MASKBIT
#define CXL_RP_MSI_NR_VECTOR            2

/* Copied from the gen root port which we derive */
#define GEN_PCIE_ROOT_PORT_AER_OFFSET 0x100
#define GEN_PCIE_ROOT_PORT_ACS_OFFSET \
    (GEN_PCIE_ROOT_PORT_AER_OFFSET + PCI_ERR_SIZEOF)
#define CXL_ROOT_PORT_DVSEC_OFFSET \
    (GEN_PCIE_ROOT_PORT_ACS_OFFSET + PCI_ACS_SIZEOF)

typedef struct CXLRootPort {
    /*< private >*/
    PCIESlot parent_obj;

    CXLComponentState cxl_cstate;
    PCIResReserve res_reserve;
    uint32_t gpf_phase1_timeout_ms;
    uint32_t gpf_phase2_timeout_ms;
} CXLRootPort;

DECLARE_INSTANCE_CHECKER(CXLRootPort, CXL_ROOT_PORT, TYPE_CXL_ROOT_PORT)

static uint16_t cxl_rp_encode_gpf_timeout_ms(uint32_t timeout_ms)
{
    uint64_t duration_us = (uint64_t)timeout_ms * 1000;
    unsigned scale = 0;

    while (duration_us > 15 && scale < 15) {
        duration_us = DIV_ROUND_UP(duration_us, 10);
        scale++;
    }
    return (scale << 8) | duration_us;
}

static uint32_t cxl_rp_decode_gpf_timeout_ms(uint16_t control)
{
    uint64_t duration_us = control & 0xf;
    unsigned scale = (control >> 8) & 0xf;

    while (scale-- && duration_us <= UINT64_MAX / 10) {
        duration_us *= 10;
    }
    return MIN(DIV_ROUND_UP(duration_us, 1000), UINT32_MAX);
}

bool cxl_rp_get_gpf_timeout_ms(PCIDevice *device, unsigned phase,
                               uint32_t *timeout_ms, Error **errp)
{
    CXLRootPort *crp;
    uint16_t offset;
    uint16_t control;

    if (!device || !timeout_ms || (phase != 1 && phase != 2) ||
        !object_dynamic_cast(OBJECT(device), TYPE_CXL_ROOT_PORT)) {
        error_setg(errp, "CXL GPF endpoint must be below a CXL Root Port");
        return false;
    }
    crp = CXL_ROOT_PORT(device);
    offset = crp->cxl_cstate.dvsecs[GPF_PORT_DVSEC].lob;
    control = pci_get_word(device->config + offset +
        (phase == 1 ? offsetof(CXLDVSECPortGPF, phase1_ctrl) :
                      offsetof(CXLDVSECPortGPF, phase2_ctrl)));
    *timeout_ms = cxl_rp_decode_gpf_timeout_ms(control);
    if (!*timeout_ms) {
        error_setg(errp, "CXL Root Port GPF Phase %u timeout is disabled",
                   phase);
        return false;
    }
    return true;
}

/*
 * If two MSI vector are allocated, Advanced Error Interrupt Message Number
 * is 1. otherwise 0.
 * 17.12.5.10 RPERRSTS,  32:27 bit Advanced Error Interrupt Message Number.
 */
static uint8_t cxl_rp_aer_vector(const PCIDevice *d)
{
    switch (msi_nr_vectors_allocated(d)) {
    case 1:
        return 0;
    case 2:
        return 1;
    case 4:
    case 8:
    case 16:
    case 32:
    default:
        break;
    }
    abort();
    return 0;
}

static int cxl_rp_interrupts_init(PCIDevice *d, Error **errp)
{
    int rc;

    rc = msi_init(d, CXL_RP_MSI_OFFSET, CXL_RP_MSI_NR_VECTOR,
                  CXL_RP_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_64BIT,
                  CXL_RP_MSI_SUPPORTED_FLAGS & PCI_MSI_FLAGS_MASKBIT,
                  errp);
    if (rc < 0) {
        assert(rc == -ENOTSUP);
    }

    return rc;
}

static void cxl_rp_interrupts_uninit(PCIDevice *d)
{
    msi_uninit(d);
}

static void latch_registers(CXLRootPort *crp)
{
    uint32_t *reg_state = crp->cxl_cstate.crb.cache_mem_registers;
    uint32_t *write_msk = crp->cxl_cstate.crb.cache_mem_regs_write_mask;

    cxl_component_register_init_common(reg_state, write_msk, CXL2_ROOT_PORT, true);
}

static void build_dvsecs(CXLRootPort *crp)
{
    CXLComponentState *cxl = &crp->cxl_cstate;
    uint8_t *dvsec;

    dvsec = (uint8_t *)&(CXLDVSECPortExt){ 0 };
    cxl_component_create_dvsec(cxl, CXL2_ROOT_PORT,
                               EXTENSIONS_PORT_DVSEC_LENGTH,
                               EXTENSIONS_PORT_DVSEC,
                               EXTENSIONS_PORT_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECPortGPF){
        .rsvd        = 0,
        .phase1_ctrl = cxl_rp_encode_gpf_timeout_ms(
            crp->gpf_phase1_timeout_ms),
        .phase2_ctrl = cxl_rp_encode_gpf_timeout_ms(
            crp->gpf_phase2_timeout_ms),
    };
    cxl_component_create_dvsec(cxl, CXL2_ROOT_PORT,
                               GPF_PORT_DVSEC_LENGTH, GPF_PORT_DVSEC,
                               GPF_PORT_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECPortFlexBus){
        .cap                     = 0x26, /* IO, Mem, non-MLD */
        .ctrl                    = 0x2,
        .status                  = 0x6, /* 256B flit, no 68B */
        .rcvd_mod_ts_data_phase1 = 0xef,
    };
    cxl_component_create_dvsec(cxl, CXL2_ROOT_PORT,
                               PCIE_CXL3_FLEXBUS_PORT_DVSEC_LENGTH,
                               PCIE_FLEXBUS_PORT_DVSEC,
                               PCIE_CXL3_FLEXBUS_PORT_DVSEC_REVID, dvsec);

    dvsec = (uint8_t *)&(CXLDVSECRegisterLocator){
        .rsvd         = 0,
        .reg0_base_lo = RBI_COMPONENT_REG | CXL_COMPONENT_REG_BAR_IDX,
        .reg0_base_hi = 0,
    };
    cxl_component_create_dvsec(cxl, CXL2_ROOT_PORT,
                               REG_LOC_DVSEC_LENGTH, REG_LOC_DVSEC,
                               REG_LOC_DVSEC_REVID, dvsec);
}

static void cxl_rp_realize(DeviceState *dev, Error **errp)
{
    PCIDevice *pci_dev     = PCI_DEVICE(dev);
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(dev);
    CXLRootPort *crp       = CXL_ROOT_PORT(dev);
    CXLComponentState *cxl_cstate = &crp->cxl_cstate;
    ComponentRegisters *cregs = &cxl_cstate->crb;
    MemoryRegion *component_bar = &cregs->component_registers;
    Error *local_err = NULL;

    if (!crp->gpf_phase1_timeout_ms || !crp->gpf_phase2_timeout_ms ||
        crp->gpf_phase1_timeout_ms > 150000 ||
        crp->gpf_phase2_timeout_ms > 150000) {
        error_setg(errp, "CXL Root Port GPF timeouts must be between 1 and "
                   "150000 ms");
        return;
    }

    rpc->parent_realize(dev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    int rc =
        pci_bridge_qemu_reserve_cap_init(pci_dev, 0, crp->res_reserve, errp);
    if (rc < 0) {
        rpc->parent_class.exit(pci_dev);
        return;
    }

    if (!crp->res_reserve.io || crp->res_reserve.io == -1) {
        pci_word_test_and_clear_mask(pci_dev->wmask + PCI_COMMAND,
                                     PCI_COMMAND_IO);
        pci_dev->wmask[PCI_IO_BASE]  = 0;
        pci_dev->wmask[PCI_IO_LIMIT] = 0;
    }

    cxl_cstate->dvsec_offset = CXL_ROOT_PORT_DVSEC_OFFSET;
    cxl_cstate->pdev = pci_dev;
    build_dvsecs(crp);

    cxl_component_register_block_init(OBJECT(pci_dev), cxl_cstate,
                                      TYPE_CXL_ROOT_PORT);

    pci_register_bar(pci_dev, CXL_COMPONENT_REG_BAR_IDX,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                     component_bar);
}

static void cxl_rp_reset_hold(Object *obj, ResetType type)
{
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(obj);
    CXLRootPort *crp = CXL_ROOT_PORT(obj);

    if (rpc->parent_phases.hold) {
        rpc->parent_phases.hold(obj, type);
    }

    latch_registers(crp);
}

static const Property gen_rp_props[] = {
    DEFINE_PROP_UINT32("bus-reserve", CXLRootPort, res_reserve.bus, -1),
    DEFINE_PROP_SIZE("io-reserve", CXLRootPort, res_reserve.io, -1),
    DEFINE_PROP_SIZE("mem-reserve", CXLRootPort, res_reserve.mem_non_pref, -1),
    DEFINE_PROP_SIZE("pref32-reserve", CXLRootPort, res_reserve.mem_pref_32,
                     -1),
    DEFINE_PROP_SIZE("pref64-reserve", CXLRootPort, res_reserve.mem_pref_64,
                     -1),
    DEFINE_PROP_PCIE_LINK_SPEED("x-speed", PCIESlot,
                                speed, PCIE_LINK_SPEED_64),
    DEFINE_PROP_PCIE_LINK_WIDTH("x-width", PCIESlot,
                                width, PCIE_LINK_WIDTH_32),
    DEFINE_PROP_BOOL("x-256b-flit", PCIESlot, flitmode, false),
    DEFINE_PROP_UINT32("x-gpf-phase1-timeout-ms", CXLRootPort,
                       gpf_phase1_timeout_ms, 150000),
    DEFINE_PROP_UINT32("x-gpf-phase2-timeout-ms", CXLRootPort,
                       gpf_phase2_timeout_ms, 10000),
};

static void cxl_rp_dvsec_write_config(PCIDevice *dev, uint32_t addr,
                                      uint32_t val, int len)
{
    CXLRootPort *crp = CXL_ROOT_PORT(dev);

    if (range_contains(&crp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC], addr)) {
        uint8_t *reg = &dev->config[addr];
        addr -= crp->cxl_cstate.dvsecs[EXTENSIONS_PORT_DVSEC].lob;
        if (addr == PORT_CONTROL_OFFSET) {
            if (pci_get_word(reg) & PORT_CONTROL_UNMASK_SBR) {
                /* unmask SBR */
                qemu_log_mask(LOG_UNIMP, "SBR mask control is not supported\n");
            }
            if (pci_get_word(reg) & PORT_CONTROL_ALT_MEMID_EN) {
                /* Alt Memory & ID Space Enable */
                qemu_log_mask(LOG_UNIMP,
                              "Alt Memory & ID space is not supported\n");
            }
        }
    }
}

static void cxl_rp_aer_vector_update(PCIDevice *d)
{
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_GET_CLASS(d);

    if (rpc->aer_vector) {
        pcie_aer_root_set_vector(d, rpc->aer_vector(d));
    }
}

static void cxl_rp_write_config(PCIDevice *d, uint32_t address, uint32_t val,
                                int len)
{
    uint16_t slt_ctl, slt_sta;
    uint32_t root_cmd =
        pci_get_long(d->config + d->exp.aer_cap + PCI_ERR_ROOT_COMMAND);

    pcie_cap_slot_get(d, &slt_ctl, &slt_sta);
    pci_bridge_write_config(d, address, val, len);
    cxl_rp_aer_vector_update(d);
    pcie_cap_flr_write_config(d, address, val, len);
    pcie_cap_slot_write_config(d, slt_ctl, slt_sta, address, val, len);
    pcie_aer_write_config(d, address, val, len);
    pcie_aer_root_write_config(d, address, val, len, root_cmd);

    cxl_rp_dvsec_write_config(d, address, val, len);
}

static void cxl_root_port_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc        = DEVICE_CLASS(oc);
    PCIDeviceClass *k      = PCI_DEVICE_CLASS(oc);
    ResettableClass *rc    = RESETTABLE_CLASS(oc);
    PCIERootPortClass *rpc = PCIE_ROOT_PORT_CLASS(oc);

    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = CXL_ROOT_PORT_DID;
    dc->desc     = "CXL Root Port";
    k->revision  = 0;
    device_class_set_props(dc, gen_rp_props);
    k->config_write = cxl_rp_write_config;

    device_class_set_parent_realize(dc, cxl_rp_realize, &rpc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, cxl_rp_reset_hold, NULL,
                                       &rpc->parent_phases);

    rpc->aer_offset = GEN_PCIE_ROOT_PORT_AER_OFFSET;
    rpc->acs_offset = GEN_PCIE_ROOT_PORT_ACS_OFFSET;
    rpc->aer_vector = cxl_rp_aer_vector;
    rpc->interrupts_init = cxl_rp_interrupts_init;
    rpc->interrupts_uninit = cxl_rp_interrupts_uninit;

    dc->hotpluggable = false;
}

static const TypeInfo cxl_root_port_info = {
    .name = TYPE_CXL_ROOT_PORT,
    .parent = TYPE_PCIE_ROOT_PORT,
    .instance_size = sizeof(CXLRootPort),
    .class_init = cxl_root_port_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CXL_DEVICE },
        { }
    },
};

static void cxl_register(void)
{
    type_register_static(&cxl_root_port_info);
}

type_init(cxl_register);
