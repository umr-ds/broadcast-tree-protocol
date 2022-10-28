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

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>
#include <wrapper.h>
#include <structs.h>
#include <patcher.h>
#include <helper.h>
#include <channels.h>
#include <ieee80211_radiotap.h>
#include "local_wrapper.h"
#include "btp_monitor.h"

struct ether_addr broadcastaddr = {.octet = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

/* hook call to wlc_recv in wlc_bmac_recv to pre-check ether_type and send as monitor frame to host if BTP */
void wlc_recv_hook(struct wlc_info *wlc, struct sk_buff *p) {
    /* check packet length is at least d11header, phy header, management frame header and llc snap header */
    if (p != 0 && p->len >= wlc->hwrxoff + D11_PHY_HDR_LEN + sizeof(struct dot11_management_header) + sizeof(struct dot11_llc_snap_header)) {
        uint8 *wrxh = (uint8 *)(p->data);
        uint16 *wrxh16 = (uint16 *)wrxh;
        uint8 pad = 0;
        uint32 mh_length = 0;
        /* check if there is a two byte padding */
        if (wrxh16[8] & 4)
            pad = 2;
        /* check type/subtype */
        uint8 type = *(uint8 *)(wrxh + wlc->hwrxoff + pad + D11_PHY_HDR_LEN);
        if (type == 0x08) { /* data frame */
            mh_length = sizeof(struct dot11_management_header);
        } else if (type == 0x88) { /* unicast qos frame */
            mh_length = sizeof(struct dot11_qos_header);
        } else {
            goto exit;
        }
        struct dot11_management_header *mh = (struct dot11_management_header *)(wrxh + wlc->hwrxoff + pad + D11_PHY_HDR_LEN);
        struct dot11_llc_snap_header *llc = (struct dot11_llc_snap_header *)(wrxh + wlc->hwrxoff + pad + D11_PHY_HDR_LEN + mh_length);
        /* check ether_type is BTP and destination address matches own or broadcast etheraddr */
        if (llc->type == SWAP16(ETHER_TYPE_BTP)
                && (!local_memcmp((void *)&mh->da, (void *)&wlc->pub->cur_etheraddr, sizeof(struct ether_addr))
                    || !local_memcmp((void *)&mh->da, (void *)&broadcastaddr, sizeof(struct ether_addr)))) {
            /* remove d11header */
            skb_pull(p, wlc->hwrxoff + pad);
            /* forward to wlc_monitor to process headers */
            local_wlc_monitor(wlc, wrxh, p, 0);
            return;
        }
    }
exit:
    wlc_recv(wlc, p);
}
__attribute__((at(0x1C25A, "", CHIP_VER_BCM43430a1, FW_VER_7_45_41_46)))
__attribute__((at(0x1BDE8E, "", CHIP_VER_BCM43455c0, FW_VER_7_45_206)))
BLPatch(wlc_recv, wlc_recv_hook);


static int
channel2freq(struct wl_info *wl, unsigned int channel)
{
#if NEXMON_CHIP == CHIP_VER_BCM43430a1
    return wlc_phy_channel2freq(channel);
#else
    int freq = 0;
    void *ci = 0;

    wlc_phy_chan2freq_acphy(wl->wlc->band->pi, channel, &freq, &ci);

    return freq;
#endif
}

/* rebuild frame to ethernet header, radiotap header, and payload, forward to host */
void
wl_monitor_radiotap(struct wl_info *wl, struct wl_rxsts *sts, struct sk_buff *p) {
    /* remove d11 phy header to get management header */
    skb_pull(p, D11_PHY_HDR_LEN);
    /* check type/subtype */
    uint8 type = *(uint8 *)p->data;
    uint32 mh_length = 0;
    if (type == 0x08) { /* broadcast management frame */
        mh_length = sizeof(struct dot11_management_header);
    } else if (type == 0x88) { /* unicast qos frame */
        mh_length = sizeof(struct dot11_qos_header);
    }
    struct dot11_management_header *mh = (struct dot11_management_header *)p->data;
    /* remove management header to get llc snap header */
    skb_pull(p, mh_length);
    struct dot11_llc_snap_header *llc = (struct dot11_llc_snap_header *)p->data;
    /* remove llc snap header to get payload */
    skb_pull(p, sizeof(struct dot11_llc_snap_header));
    uint8 *payload = (uint8 *)p->data;
    /* alloc new packet with space for ethernet header, radiotap header, and payload, excluding fcs */
    uint32 new_len = sizeof(struct ether_header) + sizeof(struct nexmon_radiotap_header) + p->len - FCS_LENGTH; 
    struct sk_buff *p_new = pkt_buf_get_skb(wl->wlc->osh, new_len);
    if (!p_new)
        goto end;
    /* fill ethernet header */
    struct ether_header *eh = (struct ether_header *) p_new->data;
    memcpy(&eh->ether_dhost, &mh->da, sizeof(struct ether_addr));
    memcpy(&eh->ether_shost, &mh->sa, sizeof(struct ether_addr));
    eh->ether_type = llc->type;
    /* fill radiotap hedaer */
    skb_pull(p_new, sizeof(struct ether_header));
    struct nexmon_radiotap_header *frame = (struct nexmon_radiotap_header *) p_new->data;
    frame->header.it_version = 0;
    frame->header.it_pad = 0;
    frame->header.it_len = sizeof(struct nexmon_radiotap_header);
    frame->header.it_present =
          (1<<IEEE80211_RADIOTAP_TSFT)
        | (1<<IEEE80211_RADIOTAP_FLAGS)
        | (1<<IEEE80211_RADIOTAP_CHANNEL)
        | (1<<IEEE80211_RADIOTAP_DBM_ANTSIGNAL)
        | (1<<IEEE80211_RADIOTAP_DBM_ANTNOISE);
    frame->tsf.tsf_l = sts->mactime;
    frame->tsf.tsf_h = 0;
    frame->flags = 0;
    frame->chan_freq = channel2freq(wl, CHSPEC_CHANNEL(sts->chanspec));
    if (CHSPEC_IS2G(sts->chanspec))
        frame->chan_flags = (IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_DYN);
    else
        frame->chan_flags = (IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM);
    frame->dbm_antsignal = (int8)sts->signal;
    frame->dbm_antnoise = (int8)sts->noise;
    /* copy payload */
    skb_pull(p_new, sizeof(struct nexmon_radiotap_header));
    memcpy(p_new->data, payload, p->len - FCS_LENGTH);
    /* send up */
    skb_push(p_new, sizeof(struct nexmon_radiotap_header));
    skb_push(p_new, sizeof(struct ether_header));
    wl->dev->chained->funcs->xmit(wl->dev, wl->dev->chained, p_new);
    /* free original packet buffer */
end:
    skb_push(p, sizeof(struct dot11_llc_snap_header));
    skb_push(p, mh_length);
    skb_push(p, D11_PHY_HDR_LEN);
    skb_push(p, wl->wlc->hwrxoff);
    pkt_buf_free_skb(wl->wlc->osh, p, 0);
}


/* hook call to wl_monitor in wlc_monitor */
void
wl_monitor_hook(struct wl_info *wl, struct wl_rxsts *sts, struct sk_buff *p) {
    wl_monitor_radiotap(wl, sts, p);
}
__attribute__((at(0x81F620, "flashpatch", CHIP_VER_BCM43430a1, FW_VER_ALL)))
__attribute__((at(0x1A6C98, "", CHIP_VER_BCM43455c0, FW_VER_7_45_206)))
BLPatch(flash_patch_179, wl_monitor_hook);
