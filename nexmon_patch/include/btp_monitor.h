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
 * Copyright (c) 2021 NexMon Team                                          *
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

#ifndef BTP_MONITOR_H
#define BTP_MONITOR_H

struct ether_addr {
    uint8 octet[6];
} __attribute__((packed));

struct dot11_management_header {
    uint16 fc;
    uint16 durid;
    struct ether_addr da;
    struct ether_addr sa;
    struct ether_addr bssid;
    uint16 seq;
} __attribute__((packed));

struct dot11_qos_header {
    uint16 fc;
    uint16 durid;
    struct ether_addr da;
    struct ether_addr sa;
    struct ether_addr bssid;
    uint16 seq;
    uint16 qos_ctrl;
} __attribute__((packed));

struct dot11_llc_snap_header {
    uint8 dsap;
    uint8 ssap;
    uint8 ctl;
    uint8 oui[3];
    uint16 type;
} __attribute__((packed));

struct ether_header {
    struct ether_addr ether_dhost;
    struct ether_addr ether_shost;
    uint16 ether_type;
} __attribute__((packed));

#define D11_PHY_HDR_LEN 6
#define FCS_LENGTH 4

#define ETHER_TYPE_BTP 0x88df //35039

#define SWAP16(val) \
    ((uint16)((((uint16)(val) & (uint16)0x00ffU) << 8) | \
        (((uint16)(val) & (uint16)0xff00U) >> 8)))

#endif /*BTP_MONITOR_H*/
