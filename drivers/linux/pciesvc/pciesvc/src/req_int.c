// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2018,2021-2022, Pensando Systems Inc.
 */

#include "pciesvc_impl.h"
#include "req_int.h"

#define REQ_INT_NWORDS  3

#if defined(ASIC_CAPRI) || defined(ASIC_ELBA)
typedef union req_int_u {
    struct {
        u_int64_t data:32;
        u_int64_t addrdw:34;
    } __attribute__((packed));
    u_int32_t w[REQ_INT_NWORDS];
} req_int_t;

static void
req_int_set(const u_int64_t reg, const u_int64_t addr, const u_int32_t data)
{
    req_int_t in = { .data = data, .addrdw = addr >> 2 };

    pciesvc_reg_wr32w(reg, in.w, REQ_INT_NWORDS);
}

static void
req_int_get(const u_int64_t reg, u_int64_t *addrp, u_int32_t *datap)
{
    req_int_t in;

    pciesvc_reg_rd32w(reg, in.w, REQ_INT_NWORDS);
    *addrp = in.addrdw << 2;
    *datap = in.data;
}

/*
 * The pcie request hardware provides a single base register
 * CFG_TGT_REQ_INDIRECT_INT and CFG_TGT_REQ_NOTIFY_INT to
 * configure indirect/notify interrupts for all ports.
 * Each per-port interrupt is sent to the address
 * (CFG_TGT_REQ_*_INT.addrdw << 2) + (port * 4).
 *
 * If CFG_TGT_REQ_*_INT.data[31] == 0 then a "1" is written to
 * the destination address.  This is used to trigger an interrupt
 * through a write to INTR_ASSERT register.
 * If CFG_TGT_REQ_*_INT.data[31] == 1 then data written is
 *     data = CFG_TGT_REQ_*_INT.intr_data + port.
 *
 * This routine provides the abstraction to configure base register.
 * When base register is configured, it sets above described pattern
 * of interrupts for all ports.
 * 
 * So when the request is made to configure interrupt for a port, it
 * is translated to the above pattern and validated to be sure they match
 * for all other ports.
 */
int
req_int_init(const u_int64_t reg,
             const int port, u_int64_t msgaddr, addr_mode_t addr_mode,
             u_int32_t msgdata, data_mode_t data_mode)
{
    u_int64_t msgaddr0;
    u_int32_t msgdata0;
    int r = 0;

    if (MSGDATA_HAS_ADD_PORT(msgdata) && (data_mode == MDATA_ADD_PORT)) {
        return -1; // negative msgdata with add port not supported
    }
    /*
     * First time through set msgaddr0/data0 and hw to match.
     * Doesn't matter which port we configure first,
     * but subsequent ports must follow the pattern
     *     msgaddr = msgaddr0 + (port * 4)
     *     msgdata = msgdata0 + port
     */
    req_int_get(reg, &msgaddr0, &msgdata0);
#ifdef ASIC_CAPRI
    if (1) { // to fix capri upgrade for port 4
#else
    if (port == 0 || msgaddr0 == 0) {
#endif
        msgaddr0 = msgaddr - (port * 4);
        if (data_mode == MDATA_ADD_PORT) {
            msgdata0 = (msgdata - port) | MSGDATA_ADD_PORT;
        } else {
            msgdata0 = msgdata;
        }
        req_int_set(reg, msgaddr0, msgdata0);
    }

    if (msgaddr != msgaddr0 + (port * 4)) {
        r = -2;
    } else if ((data_mode == MDATA_ADD_PORT) !=
               MSGDATA_HAS_ADD_PORT(msgdata0)) {
        r = -3;
    } else if ((data_mode == MDATA_ADD_PORT) &&
               msgdata != (MSGDATA_DATA(msgdata0) + port)) {
        r = -4;
    } else if ((data_mode != MDATA_ADD_PORT) &&
               msgdata != msgdata0) {
        r = -5;
    }
    return r;
}
#endif

#ifdef ASIC_SALINA
typedef union req_int_u {
    struct {
        u_int64_t data:32;
        uint64_t addr_mode:2;
        uint64_t data_mode:2;
        uint64_t rsvd0:16;
        u_int64_t addrdw:38;
        uint64_t rsvd1:6;
    } __attribute__((packed));
    u_int32_t w[REQ_INT_NWORDS];
} req_int_t;

static void
req_int_set(const u_int64_t reg, const u_int64_t addr,
            const u_int32_t data, const uint16_t addr_mode,
            const uint16_t data_mode)
{
    req_int_t in = { .data = data, .addr_mode = addr_mode,
                     .data_mode = data_mode, .addrdw = addr >> 2 };

    pciesvc_reg_wr32w(reg, in.w, REQ_INT_NWORDS);
}

static void
req_int_get(const u_int64_t reg, u_int64_t *addrp, u_int32_t *datap, uint16_t *addr_mode, uint16_t *data_mode)
{
    req_int_t in;

    pciesvc_reg_rd32w(reg, in.w, REQ_INT_NWORDS);
    *addrp = in.addrdw << 2;
    *datap = in.data;
    *addr_mode = in.addr_mode;
    *data_mode = in.data_mode;
}

/*
 * The pcie request hardware provides a single base register
 * CFG_TGT_REQ_INDIRECT_INT and CFG_TGT_REQ_NOTIFY_INT to
 * configure indirect/notify interrupts for all ports.
 * 
 * If CFG_TGT_REQ_*_INT.data[33:32] == 0 then
 * (CFG_TGT_REQ_*_INT.addrdw << 2) will be used as msgaddr for all ports
 * If CFG_TGT_REQ_*_INT.data[33:32] == 1 then
 * (CFG_TGT_REQ_*_INT.addrdw << 2) + (port * 4) will be used as msgaddr
 * 
 * If CFG_TGT_REQ_*_INT.data[35:34] == 0 then
 * CFG_TGT_REQ_*_INT.intr_data will be used as msgdata for all ports
 * If CFG_TGT_REQ_*_INT.data[35:34] == 1 then
 * CFG_TGT_REQ_*_INT.intr_data + port will be used as msgdata
 * If CFG_TGT_REQ_*_INT.data[35:34] == 2 then
 * fixed msgdata 0x1 will be used for all ports
 * 
 * This routine provides the abstraction to configure base register.
 * When base register is configured, it sets above described pattern
 * of interrupts for all ports.
 * 
 * So when the request is made to configure interrupt for a port, it
 * is translated to the above pattern and validated to be sure they match
 * for all other ports.
 */
int
req_int_init(const u_int64_t reg,
             const int port, u_int64_t msgaddr, addr_mode_t addr_mode,
             u_int32_t msgdata, data_mode_t data_mode)
{
    u_int64_t msgaddr0;
    u_int32_t msgdata0;
    u_int16_t addr_mode0, data_mode0;
    int r = 0;

    if (MSGDATA_HAS_ADD_PORT(msgdata) && (data_mode == MDATA_ADD_PORT)) {
        return -1; // negative msgdata with add port not supported
    }
    /*
     * First time through set msgaddr0/data0 and hw to match.
     * Doesn't matter which port we configure first,
     * but subsequent ports must follow the pattern
     *     msgaddr = msgaddr0 + [(port * 4)]
     *     msgdata = msgdata0 + [port]
     * Addition of port is optional based on addr and data mode
     */
    req_int_get(reg, &msgaddr0, &msgdata0, &addr_mode0, &data_mode0);
    if (port == 0 || msgaddr0 == 0) {
        if (addr_mode == MADDR_ADD_PORT) {
            msgaddr0 = msgaddr - (port * 4);
        } else {
            msgaddr0 = msgaddr;
        }

        if (data_mode == MDATA_ADD_PORT) {
            msgdata0 = msgdata - port;
        } else {
            msgdata0 = msgdata;
        }
        req_int_set(reg, msgaddr0, msgdata0, addr_mode, data_mode);
    }

    //TODO Fix it for interrupt
    return r;
    // check msgaddr pattern for all ports
    if (addr_mode != addr_mode0) {
        r = -2;
    } else if ((addr_mode == MADDR_AS_IS) && msgaddr != msgaddr0) {
        r = -3;
    }
    // check msgdata pattern for all ports
    if (data_mode != data_mode0) {
        r = -4;
    } else if ((data_mode == MDATA_ADD_PORT) &&
               msgdata != (msgdata0 + port)) {
        r = -5;
    } else if ((data_mode != MDATA_ADD_PORT) &&
               (msgdata != msgdata0)) {
        r = -6;
    }
    return r;
}

#endif
