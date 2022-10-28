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

#ifndef LOCAL_WRAPPER_C
#define LOCAL_WRAPPER_C

#include <firmware_version.h>
#include <structs.h>
#include <stdarg.h>

#ifndef WRAPPER_H
    // if this file is not included in the wrapper.h file, create dummy functions
    #define VOID_DUMMY { ; }
    #define RETURN_DUMMY { ; return 0; }

    #define AT(CHIPVER, FWVER, ADDR) __attribute__((weak, at(ADDR, "dummy", CHIPVER, FWVER)))
#else
    // if this file is included in the wrapper.h file, create prototypes
    #define VOID_DUMMY ;
    #define RETURN_DUMMY ;
    #define AT(CHIPVER, FWVER, ADDR)
#endif

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x8467C0)
void
local_wlc_bmac_write_shm(void *wlc_hw, unsigned int offset, unsigned short v)
VOID_DUMMY

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x48570)
int
wlc_pcb_fn_set(void *pcbi, int tbl, int cls,  void (*pcb)(struct wlc_info *wlc, void *pkt, uint txs))
RETURN_DUMMY

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x42FE8)
int
wlc_attach_cb_init(void *wlc)
RETURN_DUMMY

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x845080)
uint32
wlc_bmac_cca_read_counter(void * wlc_hw, int lo_off, int hi_off)
RETURN_DUMMY

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x845C64)
int
local_wlc_bmac_read_shm(void *wlc_hw, unsigned int offset)
RETURN_DUMMY

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x880b50)
AT(CHIP_VER_BCM43455c0, FW_VER_ALL, 0x9BE0C)
int
local_memcmp(void *s1, void *s2, int n)
RETURN_DUMMY

AT(CHIP_VER_BCM43430a1, FW_VER_ALL, 0x81F410)
AT(CHIP_VER_BCM43455c0, FW_VER_ALL, 0x9C30C)
void *
local_wlc_monitor(void *wlc, void * wrxh, void *p, int wlc_if)
RETURN_DUMMY

#undef VOID_DUMMY
#undef RETURN_DUMMY
#undef AT

#endif /*LOCAL_WRAPPER_C*/
