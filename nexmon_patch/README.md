# nexmon support patch for broadcast-tree protocol userspace implementation
Wi-Fi frames with ethertype `0x88df (35039)` in their LLC that are broadcasted or destined to the own hardware address are extended with a Radiotap header (see [ieee80211_radiotap.h](https://github.com/seemoo-lab/nexmon/blob/e3c87c1e128ce6e764e8b8d5e7aa67be886646c9/patches/include/ieee80211_radiotap.h)) before beeing forwarded to the host as Ethernet frames. A corresponding frame ending up at the host has the following structure:
```C
struct btp_frame {
    /* ethernet header */
    uint8   ether_dhost[6];
    uint8   ether_shost[6];
    uint16  ether_type;
    /* radiotap header */
    uint8   it_version;
    uint8   it_pad;
    uint16  it_len;
    uint32  it_present;
    /* radiotap fields */
    uint32  tsf_l;
    uint32  tsf_h;
    uint8   flags;
    uint8   data_rate;
    uint16  chan_freq;
    uint16  chan_flags;
    int8    dbm_antsignal;
    int8    dbm_antnoise;   /* constant value -91 for bcm43430a1 */
    /* btp header */
    btp_header_t btp;
    /* btp frame type specific data */
    ...
};
```

## Installing the patch on a Raspberry Pi 3B (bcm43430a1)
1. Download and setup [nexmon](https://nexmon.org/) (commit 1ad6a827e92efa8f531594c85d6cdbc184fee3e8 or newer)
2. Copy this directory to `/home/pi/nexmon/patches/bcm43430a1/7_45_41_46/nexmon_btp`
3. Change directory to `/home/pi/nexmon/patches/bcm43430a1/7_45_41_46/nexmon_btp`
4. Run `sudo -E make install-firmware`

## Installing the patch on a Raspberry Pi 3B+/4B (bcm43455c0)
1. Download and setup [nexmon](https://nexmon.org/) (commit e3c87c1e128ce6e764e8b8d5e7aa67be886646c9 or newer)
2. Copy this directory to `/home/pi/nexmon/patches/bcm43455c0/7_45_206/nexmon_btp`
3. Change directory to `/home/pi/nexmon/patches/bcm43455c0/7_45_206/nexmon_btp`
4. Run `sudo -E make install-firmware`
