#ifndef __TREE_H__
#define __TREE_H__

#include "btp.h"
#include "hashmap.h"

#define MAX_BREADTH 10
#define MAX_DEPTH 20
#define MAX_TTL ((MAX_DEPTH * 2) + 1)
#define HASHMAP_KEY_SIZE 18

/**
 * State of our parent
 */
typedef struct {
    mac_addr_t addr;
    int8_t high_pwr; // The power at which the parent does currently broadcast data frames
    int8_t snd_high_pwr; // The power at which the parent WOULD broadacst data frames, if its furthest child were to disconnect
    int8_t own_pwr; // The minimum power with which the parent has to broadcast to reach us
    uint64_t last_seen; // When did we last receive any frame from this node
    bool valid; // Whether the parent is used
} parent_t;

/**
 * State of one of our children
 */
typedef struct {
    mac_addr_t addr;
    int8_t tx_pwr; // minimum power with which we have to broadcast to reach this child
    bool game_fin; // whether the child has finished its part of the game
} child_t;

/**
 * Our own state
 */
typedef struct {
    bool is_source; // whether we are the rood of the broadcast tree
    int payload_fd; // File descriptor to the file to be sent
    struct hashmap_s *children; // hashmap of currently connected children
    struct hashmap_s *parent_blocklist; // parents that refused request are ignored
    int8_t max_pwr; // maximum power at which we are able (or willing) to broadcast
    int8_t high_pwr; // the power at which we currently broadcast data frames
    int8_t snd_high_pwr; // the power at which we WOULD broadacst data frames, if our furthest child were to disconnect
    mac_addr_t laddr; // local mac address
    parent_t parent; // currently connected parent
    parent_t pending_parent; // a new parent to which we are currently trying to connect
    parent_t prev_parent; // a parent that we were connected to
    uint32_t tree_id; // the tree to which we belong
    bool game_fin; // whether we have finished our part of the game
    uint8_t round_unchanged_cnt; // counter for game rounds without topology changes. if reaches max, game ends
    char if_name[IFNAMSIZ]; // the interface name to be used
    int sockfd;
} self_t;

#endif // __TREE_H__
