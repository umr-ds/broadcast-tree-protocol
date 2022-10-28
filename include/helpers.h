#ifndef __HELPERS_H__
#define __HELPERS_H__

#include "time.h"

#include "btp.h"

uint64_t get_time_msec(void);

/**
 * Generate a (hopefully unique) id for a new braodcast tree.
 * This is done running the source node's mac address together with the current timestamp through a very simple hashing function.
 *
 * @param laddr: MAC address of the source node of the new tree
 */
uint32_t gen_tree_id(void);

/**
 *
 */
void hexdump(const void *buf, size_t size);

/**
 * Pretty-print a BTP-frame
 */
void pprint_frame(eth_radio_btp_t *in_frame);

/**
 * Check, whether the given MAC address is already registered as a child.
 */
bool already_child(mac_addr_t potential_child_addr);

/**
 * This function builds a btp frame from the given fields.
 * The result is in the out parameter.
 */
void build_frame(eth_btp_t *out, mac_addr_t daddr, uint8_t recv_err, uint8_t mutex,
                 frame_t frame_type, uint32_t tree_id, int8_t tx_pwr);

int8_t get_tx_pwr(void);

bool set_tx_pwr(int8_t tx_pwr);

int8_t get_max_tx_pwr(void);

bool set_max_tx_pwr(void);

int8_t get_snd_pwr(void);

bool all_children_fin(void);

char *mac_to_str(mac_addr_t addr);

void prepare_key(mac_addr_t addr, char *res);

int8_t set_pwr(int8_t pwr);

#endif // __HELPERS_H__
