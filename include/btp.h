#ifndef __BTP_H__
#define __BTP_H__

#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>

#include <iwlib.h>

#define MTU 1500
#define BTP_HEADER_SIZE sizeof(eth_btp_t)
#define BTP_PAYLOAD_HEADER_SIZE (sizeof(btp_payload_t) + BTP_HEADER_SIZE)
#define MAX_PAYLOAD (MTU - (BTP_PAYLOAD_HEADER_SIZE))

#define BTP_ETHERTYPE 35039

#define MINIMAL_SNR 5

typedef uint8_t mac_addr_t[6];

typedef enum {
    data,
    end_of_game,
    parent_revocaction,
    child_reject,
    child_confirm,
    child_request,
    discovery,
    ping_to_source
} frame_t;

/**
 * Radio information required for computing transmission power.
 * For this to work, you have to install the nexmon patch.
 */
typedef struct {
    /* radiotap header */
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
    /* radiotap fields */
    uint32_t tsf_l;
    uint32_t tsf_h;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t chan_freq;
    uint16_t chan_flags;
    int8_t dbm_antsignal;
    int8_t dbm_antnoise;   /* constant value -91 for bcm43430a1 */
} __attribute__((packed)) radiotap_header_t;

/**
 * Common header of all BTP-frames
 */
typedef struct {
    uint8_t recv_err: 1; // flag set if the channel has been very noisy; NOTE: Why? Really needed? Might remove.
    uint8_t game_fin: 1; // flag set if the node has already finished its game
    uint8_t mutex: 1; // flags set if something-something mutex
    uint8_t unused: 2;
    frame_t frame_type: 3; // see frame_t enum
    uint32_t tree_id; // unique ID for each broadcast-tree
    int8_t tx_pwr; // power with which this frame has been sent
    mac_addr_t parent_addr; // address of the parent of the sending node
    int8_t high_pwr; // power with which the sending node sends data frames
    int8_t snd_high_pwr; // power with which the sending node WOULD send data frames, if its furthest child were to disconnect
} __attribute__((packed)) btp_header_t;

/**
 * Common frame structure of all BTP-frames
 * WITH RADIOTAP
 */
typedef struct {
    struct ether_header eth;
    radiotap_header_t radiotap;
    btp_header_t btp;
} __attribute__((packed)) eth_radio_btp_t;

/**
 * Common frame structure of all BTP-frames
 */
typedef struct {
    struct ether_header eth;
    btp_header_t btp;
} __attribute__((packed)) eth_btp_t;

typedef struct {
    uint16_t seq_num; // payload sequence number - separate from btp sequence number
    uint32_t payload_len;
    uint16_t payload_chunk_len;
    uint8_t ttl;
} __attribute__((packed)) btp_payload_t;

/**
 * Payload frames are used to transmit payload data after the tree has been built
 * WITH RADIOTAP
 */
typedef struct {
    eth_radio_btp_t btp_frame;
    btp_payload_t payload_header;
    uint8_t payload[MAX_PAYLOAD];
} __attribute__((packed)) eth_radio_btp_payload_t;

/**
 * Payload frames are used to transmit payload data after the tree has been built
 */
typedef struct {
    eth_btp_t btp_frame;
    btp_payload_t payload_header;
    uint8_t payload[MAX_PAYLOAD];
} __attribute__((packed)) eth_btp_payload_t;

/**
 * Frame for the Ping-to-Source cycle avoidance scheme
 * WITH RADIOTAP
 */
typedef struct {
    eth_radio_btp_t btp_frame;
    uint8_t ttl;
    mac_addr_t sender;
    mac_addr_t old_parent;
    mac_addr_t new_parent;
} __attribute__((packed)) eth_radio_btp_pts_t;

/**
 * Frame for the Ping-to-Source cycle avoidance scheme
 */
typedef struct {
    eth_btp_t btp_frame;
    uint8_t ttl;
    mac_addr_t sender;
    mac_addr_t old_parent;
    mac_addr_t new_parent;
} __attribute__((packed)) eth_btp_pts_t;

bool self_is_connected(void);

/**
 * Initialises the construction of a new broadcast-tree
 */
void broadcast_discovery(void);

/**
 * Parse the common btp-header
 *
 * @param in_frame: Pointer to a btp_frame_t struct which will serve as the destination
 * @param racv_frame: Pointer to a raw bitstream as it was read from raw socket
 */
void parse_header(eth_radio_btp_t *in_frame, uint8_t *recv_frame);

/**
 * Do stuf with a received packet
 *
 * @param racv_frame: Pointer to a raw bitstream as it was read from raw socket
 */
void handle_packet(uint8_t *recv_frame);

/**
 * Initializier for self_t struct, that represents our identity in the tree
 *
 * @param laddr: Our own mac address
 * @param payload: The payload the source shall send
 * @param if_name: The interface's name
 * @param sockfd: Socket that is used for sending, receiving and IOTCTLs
 */
void init_self(mac_addr_t laddr, char *payload, char *if_name, int sockfd);

/**
 * Performs the bookkeeping at the end of a game round
 */
void game_round(uint64_t cur_time);

void disconnect_from_parent(void);

#endif // __BTP_H__
