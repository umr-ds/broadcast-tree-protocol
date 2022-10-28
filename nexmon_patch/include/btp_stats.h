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

#ifndef BTP_STATS_H
#define BTP_STATS_H

#define wreg32(r, v)    (*(volatile uint32*)(r) = (uint32)(v))
#define rreg32(r)       (*(volatile uint32*)(r))
#define wreg16(r, v)    (*(volatile uint16*)(r) = (uint16)(v))
#define rreg16(r)       (*(volatile uint16*)(r))
#define wreg8(r, v)     (*(volatile uint8*)(r) = (uint8)(v))
#define rreg8(r)        (*(volatile uint8*)(r))

#define BCM_REFERENCE(data) ((void)(data))

#define W_REG(osh, r, v) do { \
    BCM_REFERENCE(osh); \
    switch (sizeof(*(r))) { \
    case sizeof(uint8): wreg8((void *)(r), (v)); break; \
    case sizeof(uint16):    wreg16((void *)(r), (v)); break; \
    case sizeof(uint32):    wreg32((void *)(r), (v)); break; \
    } \
} while (0)

#define R_REG(osh, r) ({ \
    __typeof(*(r)) __osl_v; \
    BCM_REFERENCE(osh); \
    switch (sizeof(*(r))) { \
    case sizeof(uint8): __osl_v = rreg8((void *)(r)); break; \
    case sizeof(uint16):    __osl_v = rreg16((void *)(r)); break; \
    case sizeof(uint32):    __osl_v = rreg32((void *)(r)); break; \
    } \
    __osl_v; \
})

/* status field bit definitions */
#define TX_STATUS_FRM_RTX_MASK  0xF000
#define TX_STATUS_FRM_RTX_SHIFT 12
#define TX_STATUS_RTS_RTX_MASK  0x0F00
#define TX_STATUS_RTS_RTX_SHIFT 8
#define TX_STATUS_MASK          0x00FE
#define TX_STATUS_PMINDCTD      (1 << 7)    /* PM mode indicated to AP */
#define TX_STATUS_INTERMEDIATE  (1 << 6)    /* intermediate or 1st ampdu pkg */
#define TX_STATUS_AMPDU         (1 << 5)    /* AMPDU status */
#define TX_STATUS_SUPR_MASK     0x1C        /* suppress status bits (4:2) */
#define TX_STATUS_SUPR_SHIFT    2
#define TX_STATUS_ACK_RCV       (1 << 1)    /* ACK received */
#define TX_STATUS_VALID         (1 << 0)    /* Tx status valid (corerev >= 5) */
#define TX_STATUS_NO_ACK        0
#define TX_STATUS_BE            (TX_STATUS_ACK_RCV | TX_STATUS_PMINDCTD)

#define M_CCA_STATS_BLK_PRE40 (0x360 * 2)

#define M_CCA_TXDUR_L   0x0
#define M_CCA_TXDUR_H   0x2
#define M_CCA_INBSS_L   0x4
#define M_CCA_INBSS_H   0x6
#define M_CCA_OBSS_L    0x8
#define M_CCA_OBSS_H    0xa
#define M_CCA_NOCTG_L   0xc
#define M_CCA_NOCTG_H   0xe
#define M_CCA_NOPKT_L   0x10
#define M_CCA_NOPKT_H   0x12
#define M_MAC_DOZE_L    0x14
#define M_MAC_DOZE_H    0x16
#define M_CCA_TXOP_L    0x18
#define M_CCA_TXOP_H    0x1a
#define M_CCA_GDTXDUR_L 0x1c
#define M_CCA_GDTXDUR_H 0x1e
#define M_CCA_BDTXDUR_L 0x20
#define M_CCA_BDTXDUR_H 0x22

#define M_UCODE_MACSTAT (0x70 * 2)
#define MACSTAT_ADDR(offset) (M_UCODE_MACSTAT + 2 * (offset))

typedef enum {
    MCSTOFF_TXFRAME = 0,
    MCSTOFF_TXRTSFRM = 1,
    MCSTOFF_TXCTSFRM = 2,
    MCSTOFF_TXACKFRM = 3,
    MCSTOFF_TXDNLFRM = 4,
    MCSTOFF_TXBCNFRM = 5,       /* 5 */
    MCSTOFF_TXFUNFL = 6,        /* 6ea (number of tx/rx fifo) */
    MCSTOFF_TXAMPDU = 12,
    MCSTOFF_TXMPDU = 13,
    MCSTOFF_TXTPLUNFL = 14,
    MCSTOFF_TXPHYERR = 15,
    MCSTOFF_RXGOODUCAST = 16,
    MCSTOFF_RXGOODOCAST = 17,
    MCSTOFF_RXFRMTOOLONG = 18,
    MCSTOFF_RXFRMTOOSHRT = 19,
    MCSTOFF_RXANYERR = 20,      /* 20 */
    MCSTOFF_RXBADFCS = 21,
    MCSTOFF_RXBADPLCP = 22,
    MCSTOFF_RXCRSGLITCH = 23,
    MCSTOFF_RXSTRT = 24,
    MCSTOFF_RXDFRMUCASTMBSS = 25,   /* 25 */
    MCSTOFF_RXMFRMUCASTMBSS = 26,
    MCSTOFF_RXCFRMUCAST = 27,
    MCSTOFF_RXRTSUCAST = 28,
    MCSTOFF_RXCTSUCAST = 29,
    MCSTOFF_RXACKUCAST = 30,        /* 30 */
    MCSTOFF_RXDFRMOCAST = 31,
    MCSTOFF_RXMFRMOCAST = 32,
    MCSTOFF_RXCFRMOCAST = 33,
    MCSTOFF_RXRTSOCAST = 34,
    MCSTOFF_RXCTSOCAST = 35,        /* 35 */
    MCSTOFF_RXDFRMMCAST = 36,
    MCSTOFF_RXMFRMMCAST = 37,
    MCSTOFF_RXCFRMMCAST = 38,
    MCSTOFF_RXBEACONMBSS = 39,
    MCSTOFF_RXDFRMUCASTOBSS = 40,   /* 40 */
    MCSTOFF_RXBEACONOBSS = 41,
    MCSTOFF_RXRSPTMOUT = 42,
    MCSTOFF_BCNTXCANCL = 43,
    MCSTOFF_RXNODELIM = 44,
    MCSTOFF_RXF0OVFL = 45,      /* 45 */
    MCSTOFF_DBGOFF46_CNT = 46,      /* correv < 40 */
    MCSTOFF_DBGOFF47_CNT = 47,      /* correv < 40 */
    MCSTOFF_DBGOFF48_CNT = 48,      /* correv < 40 */
    MCSTOFF_PMQOVFL = 49,
    MCSTOFF_RXCGPRQFRM = 50,        /* 50 */
    MCSTOFF_RXCGPRSQOVFL = 51,
    MCSTOFF_TXCGPRSFAIL = 52,
    MCSTOFF_TXCGPRSSUC = 53,
    MCSTOFF_PRS_TIMEOUT = 54,
    MCSTOFF_TXRTSFAIL = 55,     /* 55 */
    MCSTOFF_TXUCAST = 56,
    MCSTOFF_TXINRTSTXOP = 57,
    MCSTOFF_RXBACK = 58,
    MCSTOFF_TXBACK = 59,
    MCSTOFF_BPHYGLITCH = 60,        /* 60 */
    MCSTOFF_PHYWATCH = 61,      /* correv < 40 */
    MCSTOFF_RXTOOLATE = 62,
    MCSTOFF_BPHY_BADPLCP = 63
} macstat_offset_t;

struct btp_stats {
    uint32 txdur;
    uint32 rxdur;
    uint32 ibss;
    uint32 obss;
    uint32 noctg;
    uint32 nopkt;
    uint32 txopp;
    uint32 slot_time_txop;
    uint32 gdtxdur;
    uint32 bdtxdur;
    uint32 txfrm;
    uint32 txrtsfrm;
    uint32 txctsfrm;
    uint32 txackfrm;
    uint32 txdnlfrm;
    uint32 txbcnfrm;
    uint32 txampdufrm;
    uint32 txmpdufrm;
    uint32 txucast;
    uint32 rxstrt;
    uint32 crsglitch;
    uint32 badplcp;
};

struct stats_udp_frame {
    struct ethernet_ip_udp_header hdrs;
    struct btp_stats stats;
} __attribute__((packed));

#endif /* BTP_STATS_H */
