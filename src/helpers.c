#include <time.h>
#include <tree.h>

#include "libexplain/ioctl.h"
#include "log.h"
#include "helpers.h"
#include "hashmap.h"

typedef struct {
    int8_t high_pwr;
    int8_t snd_high_pwr;
} snd_pwr_iterator_t;

extern self_t self;
extern bool flood;

int8_t set_pwr(int8_t pwr) {
    if (flood) {
        return self.max_pwr;
    } else {
        return pwr;
    }
}

int hashmap_child_fin(void *const context, void *const value);
int hashmap_snd_pwr(void *const context, void *const value);

int hashmap_child_fin(void *const context, void *const value) {
    (void) (context);
    child_t *tmp_child = (child_t *) value;

    log_debug("Game fin status. [addr: %s, game_fin: %s]", mac_to_str(tmp_child->addr),
              tmp_child->game_fin ? "true" : "false");

    return tmp_child->game_fin ? true : false;
}

bool all_children_fin() {
    if (hashmap_num_entries(self.children) == 0) {
        log_debug("Have no children.");
        return true;
    }

    return hashmap_iterate(self.children, hashmap_child_fin, NULL) == 0;
}

int hashmap_snd_pwr(void *const context, void *const value) {
    snd_pwr_iterator_t *snd_pwr_iterator = (snd_pwr_iterator_t *) context;
    child_t *tmp_child = (child_t *) value;

    if (tmp_child->tx_pwr > snd_pwr_iterator->high_pwr) {
        snd_pwr_iterator->snd_high_pwr = snd_pwr_iterator->high_pwr;
        snd_pwr_iterator->high_pwr = tmp_child->tx_pwr;
    } else if (tmp_child->tx_pwr > snd_pwr_iterator->snd_high_pwr) {
        snd_pwr_iterator->snd_high_pwr = tmp_child->tx_pwr;
    }

    return 1;
}

int8_t get_snd_pwr() {
    snd_pwr_iterator_t *snd_pwr_iterator = malloc(sizeof(snd_pwr_iterator_t));

    snd_pwr_iterator->high_pwr = 0;
    snd_pwr_iterator->snd_high_pwr = 0;

    hashmap_iterate(self.children, hashmap_snd_pwr, snd_pwr_iterator);

    int8_t snd_high_pwr = snd_pwr_iterator->snd_high_pwr;

    return snd_high_pwr;
}

uint64_t get_time_msec() {
    struct timeval tval;
    if (gettimeofday(&tval, NULL) != 0) {
        log_error("Get time returned an error: %s", strerror(errno));
    }
    return ((tval.tv_sec * 1000000) + tval.tv_usec) / 1000;
}

bool already_child(mac_addr_t potential_child_addr) {
    char key[HASHMAP_KEY_SIZE] = {0x0};
    prepare_key(potential_child_addr, key);
    child_t *tmp_child = hashmap_get(self.children, key, HASHMAP_KEY_SIZE);
    if (tmp_child != NULL) {
        return true;
    }

    return false;
}

uint32_t gen_tree_id() {
    // TODO: seed for random numbger generator
    srand(time(0));
    return rand() % UINT32_MAX;
}

bool set_max_tx_pwr() {
    log_debug("Setting max TX power.");
    int8_t max_tx_pwr;
    if ((max_tx_pwr = get_max_tx_pwr()) < 0) {
        return false;
    }

    if (!set_tx_pwr(max_tx_pwr)) {
        return false;
    }

    return true;
}

bool set_tx_pwr(int8_t tx_pwr) {
    struct iwreq wrq;
    wrq.u.txpower.value = (int32_t) tx_pwr;
    wrq.u.txpower.fixed = 1;
    wrq.u.txpower.disabled = 0;
    wrq.u.txpower.flags = IW_TXPOW_DBM;

    if (iw_set_ext(self.sockfd, self.if_name, SIOCSIWTXPOW, &wrq) < 0) {
        log_error("Could not set txpower. [error: %s]", explain_ioctl(self.sockfd, SIOCSIWTXPOW, &wrq));
        return false;
    }

    return true;
}

int8_t get_tx_pwr() {
    struct iwreq *wrq = malloc(sizeof(struct iwreq));
    memset(wrq, 0, sizeof(struct iwreq));
    int32_t dbm;

    int res;
    /* Get current Transmit Power */
    if ((res = iw_get_ext(self.sockfd, self.if_name, SIOCGIWTXPOW, wrq)) >= 0) {
        if (wrq->u.txpower.disabled) {
            log_error("Transmission is disabled.");
            free(wrq);
            return -1;
        } else {
            if (wrq->u.txpower.flags & IW_TXPOW_MWATT) {
                dbm = iw_mwatt2dbm(wrq->u.txpower.value);
            } else {
                dbm = wrq->u.txpower.value;
            }
            free(wrq);
            return (int8_t) dbm;
        }
    } else {
        log_error("Could not get current txpower. [%s]", explain_ioctl(self.sockfd, SIOCGIWTXPOW, wrq));
        free(wrq);
        return (int8_t) res;
    }
}

int8_t get_max_tx_pwr() {
    int8_t cur_tx_pwr;
    if ((cur_tx_pwr = get_tx_pwr()) < 0) {
        return -1;
    }

    if (!set_tx_pwr(INT8_MAX)) {
        return -1;
    }

    int8_t max_tx_pwr;
    if ((max_tx_pwr = get_tx_pwr()) < 0) {
        return -1;
    }

    if (!set_tx_pwr(cur_tx_pwr)) {
        return -1;
    }

    log_debug("Got max tx power. [max_tx_pwr: %i]", max_tx_pwr);

    return max_tx_pwr;
}

void hexdump(const void *buf, size_t size) {
    char chars[17];
    unsigned char *buf_cpy = malloc(size);
    memcpy(buf_cpy, buf, size);
    chars[16] = '\0';

    size_t data_index;
    size_t padding_index;

    for (data_index = 0; data_index < size; ++data_index) {
        printf("%02x ", (buf_cpy)[data_index]);

        if ((buf_cpy)[data_index] >= ' ' && (buf_cpy)[data_index] <= '~') {
            chars[data_index % 16] = (buf_cpy)[data_index];
        } else {
            chars[data_index % 16] = '.';
        }

        if ((data_index + 1) % 8 == 0 || data_index + 1 == size) {
            printf(" ");

            if ((data_index + 1) % 16 == 0) {
                printf("|  %s \n", chars);
            } else if (data_index + 1 == size) {
                chars[(data_index + 1) % 16] = '\0';

                if ((data_index + 1) % 16 <= 8) {
                    printf(" ");
                }

                for (padding_index = (data_index + 1) % 16; padding_index < 16; ++padding_index) {
                    printf("   ");
                }

                printf("|  %s \n", chars);
            }
        }
    }

    free(buf_cpy);
}

char *mac_to_str(mac_addr_t addr) {
    size_t res_size = sizeof(char) * HASHMAP_KEY_SIZE;
    char *mac_str = malloc(res_size);
    snprintf(mac_str, res_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

    return mac_str;
}

void prepare_key(mac_addr_t addr, char *res) {
    snprintf(res, HASHMAP_KEY_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

void pprint_frame(eth_radio_btp_t *in_frame) {
    struct ether_header eth = in_frame->eth;
    radiotap_header_t rdio = in_frame->radiotap;
    btp_header_t btp = in_frame->btp;

    log_debug("BTP Frame:\n"
              "- Ethernet:\n"
              "    Source:............%x:%x:%x:%x:%x:%x\n"
              "    Destination:.......%x:%x:%x:%x:%x:%x\n"
              "    EtherType:.........%hu\n"
              "- RadioTap Header:\n"
              "    Version:...........%hhu\n"
              "    Length:............%hu\n"
              "    Present:...........%u\n"
              "    Time Sync:.........%u%u\n"
              "    Flags:.............%hhu\n"
              "    data_rate:.........%hhu\n"
              "    Frequency:.........%hu\n"
              "    Channel Flags:.....%hu\n"
              "    Signal:............%hhi\n"
              "    Noise:.............%hhi\n"
              "- BTP:\n"
              "    Recv Error:........%hhu\n"
              "    Game Fin:..........%hhu\n"
              "    Mutex:.............%hhu\n"
              "    Frame Type:........%i\n"
              "    Tree ID:...........%u\n"
              "    TX Power:..........%hhu\n"
              "    Parent Addr:.......%x:%x:%x:%x:%x:%x\n"
              "    Highest Power:.....%hhu\n"
              "    2nd highest power:.%hhu\n",
              eth.ether_shost[0], eth.ether_shost[1], eth.ether_shost[2], eth.ether_shost[3], eth.ether_shost[4],
              eth.ether_shost[5],
              eth.ether_dhost[0], eth.ether_dhost[1], eth.ether_dhost[2], eth.ether_dhost[3], eth.ether_dhost[4],
              eth.ether_dhost[5],
              ntohs(eth.ether_type),
              rdio.it_version,
              rdio.it_len,
              rdio.it_present,
              rdio.tsf_h, rdio.tsf_l,
              rdio.flags,
              rdio.data_rate,
              rdio.chan_freq,
              rdio.chan_flags,
              rdio.dbm_antsignal,
              rdio.dbm_antnoise,
              btp.recv_err,
              btp.game_fin,
              btp.mutex,
              btp.frame_type,
              btp.tree_id,
              btp.tx_pwr,
              btp.parent_addr[0], btp.parent_addr[1], btp.parent_addr[2], btp.parent_addr[3], btp.parent_addr[4],
              btp.parent_addr[5],
              btp.high_pwr,
              btp.snd_high_pwr,
    );
}

void build_frame(eth_btp_t *out, mac_addr_t daddr, uint8_t recv_err, uint8_t mutex,
                 frame_t frame_type, uint32_t tree_id, int8_t tx_pwr) {
    out->btp.recv_err = recv_err;
    out->btp.game_fin = self.game_fin;
    out->btp.mutex = mutex;
    out->btp.frame_type = frame_type;
    out->btp.tree_id = tree_id;
    out->btp.tx_pwr = set_pwr(tx_pwr);
    out->btp.high_pwr = self.high_pwr;
    out->btp.snd_high_pwr = self.snd_high_pwr;
    if (self_is_connected()) {
        memcpy(out->btp.parent_addr, &self.parent, 6);
    }

    out->eth.ether_type = htons(BTP_ETHERTYPE);
    memcpy(out->eth.ether_dhost, daddr, 6);
    memcpy(out->eth.ether_shost, self.laddr, 6);
}
