/***************************************************************************
 *                                                                         *
 *          ###########   ###########   ##########    ##########           *
 *         ############  ############  ############  ############          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ###########   ####  ######  ##   ##   ##  ##    ######          *
 *          ###########  ####  #       ##   ##   ##  ##    #    #          *
 *                   ##  ##    ######  ##   ##   ##  ##    #    #          *
 *                   ##  ##    #       ##   ##   ##  ##    #    #          *
 *         ############  ##### ######  ##   ##   ##  ##### ######          *
 *         ###########    ###########  ##   ##   ##   ##########           *
 *                                                                         *
 *            S E C U R E   M O B I L E   N E T W O R K I N G              *
 *                                                                         *
 * This file is part of NexMon.                                            *
 *                                                                         *
 * Copyright (c) 2022 NexMon Team                                          *
 *                                                                         *
 * NexMon is free software: you can redistribute it and/or modify          *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * NexMon is distributed in the hope that it will be useful,               *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with NexMon. If not, see <http://www.gnu.org/licenses/>.          *
 *                                                                         *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h> // definition of firmware version macros
#include <debug.h>            // contains macros to access the debug hardware
#include <wrapper.h>          // wrapper definitions for functions that already exist in the firmware
#include <structs.h>          // structures that are used by the code in the firmware
#include <helper.h>           // useful helper functions
#include <patcher.h>          // macros used to craete patches such as BLPatch, BPatch, ...
#include <rates.h>            // rates used to build the ratespec for frame injection
#include <nexioctls.h>        // ioctls added in the nexmon patch
#include <capabilities.h>     // capabilities included in a nexmon patch
#include <udptunnel.h>
#include "btp_stats.h"
#include "local_wrapper.h"

extern void prepend_ethernet_ipv4_udp_header(struct sk_buff *p);

int wlc_btp_stats_read(struct wlc_hw_info *wlc_hw, struct btp_stats *stats)
{
    /* check wlc_hw->cca_shm_base, if not initialized == -1 */
    uint32 *wlc_hw_uint32 = (uint32 *)wlc_hw;
    if (wlc_hw_uint32[74] != M_CCA_STATS_BLK_PRE40)
        return -1;
    /* read shmem */
    stats->txdur = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_TXDUR_L, M_CCA_TXDUR_H);
    stats->ibss = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_INBSS_L, M_CCA_INBSS_H);
    stats->obss = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_OBSS_L, M_CCA_OBSS_H);
    stats->noctg = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_NOCTG_L, M_CCA_NOCTG_H);
    stats->nopkt = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_NOPKT_L, M_CCA_NOPKT_H);

    stats->txopp = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_TXOP_L, M_CCA_TXOP_H);
    stats->slot_time_txop = (uint32)R_REG(wlc_hw->wlc->osh, &wlc_hw->regs->ifs_slot);
    stats->gdtxdur = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_GDTXDUR_L, M_CCA_GDTXDUR_H);
    stats->bdtxdur = wlc_bmac_cca_read_counter(wlc_hw, M_CCA_BDTXDUR_L, M_CCA_BDTXDUR_H);
    stats->rxdur = stats->ibss + stats->obss + stats->noctg + stats->nopkt;

    stats->txfrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXFRAME));
    stats->txrtsfrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXRTSFRM));
    stats->txctsfrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXCTSFRM));
    stats->txackfrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXACKFRM));
    stats->txdnlfrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXDNLFRM));
    stats->txbcnfrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXBCNFRM));
    stats->txampdufrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXAMPDU));
    stats->txmpdufrm = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXMPDU));
    stats->txucast = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXUCAST));
    stats->rxstrt = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_RXSTRT));
    stats->crsglitch = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_RXCRSGLITCH));
    stats->badplcp = local_wlc_bmac_read_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_RXBADPLCP));

    return 0;
}

void wlc_bmac_clear_counter(struct wlc_hw_info *wlc_hw, uint baseaddr, int lo_off, int hi_off)
{
    local_wlc_bmac_write_shm(wlc_hw, baseaddr + hi_off, 0);
    local_wlc_bmac_write_shm(wlc_hw, baseaddr + lo_off, 0);
}

void wlc_bmac_cca_clear_counter(struct wlc_hw_info *wlc_hw, int lo_off, int hi_off)
{
    uint32 *wlc_hw_uint32 = (uint32 *)wlc_hw;
    if (wlc_hw_uint32[74] != M_CCA_STATS_BLK_PRE40)
        return;
    wlc_bmac_clear_counter(wlc_hw, wlc_hw_uint32[74], lo_off, hi_off);
}

int wlc_btp_stats_clear(struct wlc_hw_info *wlc_hw)
{
    uint32 *wlc_hw_uint32 = (uint32 *)wlc_hw;
    if (wlc_hw_uint32[74] != M_CCA_STATS_BLK_PRE40)
        return -1;
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_TXDUR_L, M_CCA_TXDUR_H);
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_INBSS_L, M_CCA_INBSS_H);
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_OBSS_L, M_CCA_OBSS_H);
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_NOCTG_L, M_CCA_NOCTG_H);
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_NOPKT_L, M_CCA_NOPKT_H);

    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_TXOP_L, M_CCA_TXOP_H);
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_GDTXDUR_L, M_CCA_GDTXDUR_H);
    wlc_bmac_cca_clear_counter(wlc_hw, M_CCA_BDTXDUR_L, M_CCA_BDTXDUR_H);

    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXFRAME), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXRTSFRM), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXCTSFRM), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXACKFRM), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXDNLFRM), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXBCNFRM), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXAMPDU), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXMPDU), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_TXUCAST), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_RXSTRT), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_RXCRSGLITCH), 0);
    local_wlc_bmac_write_shm(wlc_hw, MACSTAT_ADDR(MCSTOFF_RXBADPLCP), 0);

    return 0;
}

/* tag all packets from host with callback */
int wl_send_hook(void *src, void *dev, void *lb)
{
    // struct sk_buff *p = (struct sk_buff *)lb;

    // if (p == 0 || p->data == 0)
    // {
    //     return wl_send(src, dev, p);
    // }

    // struct ethernet_header *out_frame = (struct ethernet_header *)p->data;

    // if (out_frame->type == ntohs(35039))
    // {
    //     struct hndrte_dev *devs = (struct hndrte_dev *)dev;
    //     struct wl_info *wl = (struct wl_info *)devs->softc;
    //     *(uint8 *)(lb + 30) = (*(uint8 *)(lb + 30) & 0xF0) | 4; // WLF2_PCB1_REG
    //     wlc_btp_stats_clear(wl->wlc_hw);

    //     return wl_send(src, dev, lb);
    // }

    return wl_send(src, dev, lb);
}
__attribute__((at(0x39674, "", CHIP_VER_BCM43430a1, FW_VER_7_45_41_46)))
GenericPatch4(wl_send_hook, wl_send_hook + 1)

/* callback */
void wlc_btp_complete(struct wlc_info *wlc, void *pkt, uint txstatus)
{
    struct sk_buff *p_stats = pkt_buf_get_skb(wlc->osh, sizeof(struct stats_udp_frame));
    struct stats_udp_frame *udpfrm = (struct stats_udp_frame *)p_stats->data;
    wlc_btp_stats_read(wlc->hw, &udpfrm->stats);

    skb_pull(p_stats, sizeof(struct ethernet_ip_udp_header));
    prepend_ethernet_ipv4_udp_header(p_stats);
    wlc->wl->dev->chained->funcs->xmit(wlc->wl->dev, wlc->wl->dev->chained, p_stats);
}

int wlc_attach_cb_init_hook(struct wlc_info *wlc)
{
    int ret = wlc_attach_cb_init(wlc);
    uint32 *wlcv = (uint32 *)wlc;
    wlc_pcb_fn_set((void *)(wlcv[286]), 0, 4, wlc_btp_complete);
    return ret;
}
__attribute__((at(0x43ED6, "", CHIP_VER_BCM43430a1, FW_VER_7_45_41_46)))
BLPatch(wlc_attach_cb_init_hook, wlc_attach_cb_init_hook)
