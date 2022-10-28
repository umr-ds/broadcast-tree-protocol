#define _GNU_SOURCE

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <errno.h>
#include <poll.h>
#include <argp.h>
#include <time.h>
#include <limits.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "libexplain/socket.h"
#include "libexplain/ioctl.h"
#include <libexplain/poll.h>

#include "log.h"
#include "tree.h"
#include "btp.h"
#include "helpers.h"
#include "hashmap.h"

extern self_t self;
extern bool payload_complete;
extern bool flood;

uint16_t pending_timeout_msec;
uint16_t source_retransmit_payload_msec;
uint8_t unchanged_counter;
uint8_t tx_pwr_threshold;

int init_sock(char *if_name, char *payload);

int event_loop(uint16_t poll_timeout_msec, uint16_t discovery_bcast_interval_msec, bool omit_roll_back);

void sig_handler(int signum);

struct arguments {
    char *payload;
    bool flood;
    int log_level;
    char *log_file;
    char *interface;
    uint16_t poll_timeout_msec;
    uint16_t discovery_bcast_interval_msec;
    uint16_t pending_timeout_msec;
    uint16_t source_retransmit_payload_msec;
    uint8_t unchanged_counter;
    uint8_t tx_pwr_threshold;
    bool omit_roll_back;
};

const char *argp_program_version = "btp 0.1";
const char *argp_program_bug_address = "<sterz@mathematik.uni-marburg.de>";
static char doc[] = "BTP -- Broadcast Tree Protocol";
static char args_doc[] = "INTERFACE";
static struct argp_option options[] = {
        {"source",             's', "payload", 0, "Path to the payload to be sent (omit this option for client mode)",                        0},
        {"flood",              'd', 0,         0, "Whether to use simple flooding protocol or BTP",     0},
        {"log_level",          'l', "level",   0, "Log level\n0: QUIET, 1: TRACE, 2: DEBUG, 3: INFO (default),\n4: WARN, 5: ERROR, 6: FATAL", 1},
        {"log_file",           'f', "path",    0, "File path to log file.\nIf not present only stdout and stderr logging will be used",       1},

        {"poll_timeout",       'p', "msec",    0, "Timeout for poll syscall",                                                                 1},
        {"broadcast_timeout",  'b', "msec",    0, "How often the discovery frames should be broadcasted",                                     1},
        {"pending_timeout",    't', "msec",    0, "How long to wait for potential parent to answer",                                          1},
        {"retransmit_timeout", 'r', "msec",    0, "How long to wait for retransmitting the payload from the source",                          1},
        {"tx_pwr_threshold", 'x', "thresh", 0, "Add threshold to avoid setting tx power too low"},

        {"unchanged_counter",  'u', "number",  0, "How many rounds to wait until declaring game finished",                                    1},
        {"omit_roll_back",     'o', 0,         0, "Do not roll back tree after payload is completely received",                               1},

        {0}
};

struct sockaddr_ll L_SOCKADDR = {
        .sll_family = 0,
        .sll_protocol = 0,
        .sll_ifindex = 0,
        .sll_hatype = 0,
        .sll_pkttype = 0,
        .sll_halen = 0,
        .sll_addr = {0}
};

void sig_handler(int signum) {
    switch (signum) {
        case SIGINT:
            log_info("Received CTRL-C. [signal: %s]", strsignal(signum));
            exit(signum);
        case SIGQUIT:
            log_fatal("Dumping core. [signal: %s]", strsignal(signum));
            exit(signum);
        case SIGTERM:
            log_warn("Terminating. [signal: %s]", strsignal(signum));
            exit(signum);
        case SIGABRT:
            log_fatal("Have to abort. [signal: %s]", strsignal(signum));
            signal(signum, SIG_DFL);
            raise(signum);
            break;
        case SIGSEGV:
            log_fatal("Violated memory! [signal: %s]", strsignal(signum));
            signal(signum, SIG_DFL);
            raise(signum);
            break;
        default:
            log_error("Received signal we should not get.", strsignal(signum));
            exit(signum);
    }
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    char buf[PATH_MAX]; /* PATH_MAX incudes the \0 so +1 is not required */
    char *res;

    switch (key) {
        case 's':
            res = realpath(arg, buf);
            if (!res) {
                log_error("Could not read file. [arg= %s, err= %s]", arg, strerror(errno));
                exit(EXIT_FAILURE);
            }

            arguments->payload = res;
            break;
        case 'l':
            arguments->log_level = (int) strtol(arg, NULL, 10);
            break;
        case 'f':
            arguments->log_file = arg;
            break;
        case 'd':
            arguments->flood = true;
            break;
        case 'p':
            arguments->poll_timeout_msec = (uint16_t) strtol(arg, NULL, 10);
            break;
        case 'b':
            arguments->discovery_bcast_interval_msec = (uint16_t) strtol(arg, NULL, 10);
            break;
        case 't':
            arguments->pending_timeout_msec = (uint16_t) strtol(arg, NULL, 10);
            break;
        case 'r':
            arguments->source_retransmit_payload_msec = (uint16_t) strtol(arg, NULL, 10);
            break;
        case 'u':
            arguments->unchanged_counter = (uint8_t) strtol(arg, NULL, 10);
            break;
        case 'x':
            arguments->tx_pwr_threshold = (uint8_t) strtol(arg, NULL, 10);
        case 'o':
            arguments->omit_roll_back = true;
            break;
        case ARGP_KEY_ARG :
            if (state->arg_num >= 1) argp_usage(state);
            arguments->interface = arg;
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 1) argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc, 0, 0, 0};

int init_sock(char *if_name, char *payload) {
    log_info("Initialising socket. [interface: %s]", if_name);
    int ioctl_stat;
    int tmp_sockfd;

    struct ifreq if_idx;
    struct ifreq if_mac;

    if ((tmp_sockfd = socket(AF_PACKET, SOCK_RAW, htons(BTP_ETHERTYPE))) == -1) {
        log_error("Could not create socket: %s", explain_socket(AF_PACKET, SOCK_RAW, htons(BTP_ETHERTYPE)));
        return tmp_sockfd;
    }
    log_debug("Created socket. [sock_fd: %i]", tmp_sockfd);

    memcpy(if_idx.ifr_name, if_name, IFNAMSIZ - 1);
    ioctl_stat = ioctl(tmp_sockfd, SIOCGIFINDEX, &if_idx);
    if (ioctl_stat < 0) {
        log_error("Could not get the interface's index. [%s]", explain_ioctl(tmp_sockfd, SIOCGIFINDEX, &if_idx));
    }
    log_debug("Got interface's index.");

    memcpy(if_mac.ifr_name, if_name, IFNAMSIZ - 1);
    ioctl_stat = ioctl(tmp_sockfd, SIOCGIFHWADDR, &if_mac);
    if (ioctl_stat < 0) {
        log_error("Could not get MAC address. [%s]", explain_ioctl(tmp_sockfd, SIOCGIFHWADDR, &if_mac));
        return ioctl_stat;
    }
    log_debug("Acquired MAC address. [addr: %s]", mac_to_str((uint8_t *) if_mac.ifr_hwaddr.sa_data));

    L_SOCKADDR.sll_ifindex = if_idx.ifr_ifindex;
    L_SOCKADDR.sll_halen = ETH_ALEN;

    init_self((uint8_t *) &if_mac.ifr_hwaddr.sa_data, payload, if_name, tmp_sockfd);
    log_debug("Initialized self. [source: %s, tree_id: %u]", self.is_source ? "true" : "false", self.tree_id);

    int8_t max_tx_pwr;
    for (uint8_t retries = 0; retries < 2; retries++) {
        if ((max_tx_pwr = get_max_tx_pwr()) >= 0) {
            break;
        }

        if (retries >= 2 && max_tx_pwr < 0) {
            return -1;
        }
    }
    self.max_pwr = max_tx_pwr;
    if (flood) {
        self.high_pwr = max_tx_pwr;
        self.snd_high_pwr = max_tx_pwr;
    }
    log_debug("Figured out max sending power. [max_power: %i]", max_tx_pwr);

    return tmp_sockfd;
}

int event_loop(uint16_t poll_timeout_msec, uint16_t discovery_bcast_interval_msec, bool omit_roll_back) {
    ssize_t read_bytes;
    uint8_t recv_frame[MTU];
    memset(recv_frame, 0, MTU * sizeof(uint8_t));

    struct timespec poll_timeout = {.tv_sec = 0, .tv_nsec = 0,};
    poll_timeout.tv_sec = poll_timeout_msec / 1000;
    poll_timeout.tv_nsec = (poll_timeout_msec % 1000) * 1000000;

    sigset_t signals = { 0 };
    sigaddset(&signals, SIGINT);
    sigaddset(&signals, SIGQUIT);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGABRT);
    sigaddset(&signals, SIGSEGV);

    uint64_t bcast_send_time = get_time_msec();
    int res;
    log_info("Waiting for BTP packets.");
    while (1) {
        if (flood){
            self.game_fin = true;
        }

        // If we have received the entire payload, we can shutdown or execution.
        // If if we received the entire payload and have no children, we disconnect from our parent to notify them,
        // that we are finished.
        if (!omit_roll_back && payload_complete) {
            log_info("Received entire payload and have no children. Disconnecting from parent.");
            if (flood) {
                return 0;
            } else if (hashmap_num_entries(self.children) == 0 && self_is_connected()) {
                disconnect_from_parent();
                return 0;
            }
        }

        uint64_t cur_time = get_time_msec();
        if (cur_time - bcast_send_time > discovery_bcast_interval_msec) {
            if ((self.is_source || self_is_connected()) && !flood) {
                broadcast_discovery();
            }

            bcast_send_time = cur_time;
        }

        game_round(cur_time);
        log_debug("Evaluated game round.");

        struct pollfd pfd = {
                .fd = self.sockfd,
                .events = POLLIN
        };

        res = ppoll(&pfd, 1, &poll_timeout, &signals);

        if (res == -1) {
            log_error("Poll returned an error. [%s]", explain_poll(&pfd, 1, poll_timeout_msec));
            return res;
        }

        if (res == 0) {
            continue;
        }

        if (pfd.revents & POLLIN) {
            if ((read_bytes = recv(self.sockfd, recv_frame, MTU, 0)) >= 0) {
                log_info("Received BTP packet. [read_bytes: %i]", read_bytes);
                handle_packet(recv_frame);
            } else {
                if (errno == EINTR) {
                    memset(recv_frame, 0, MTU * sizeof(uint8_t));
                    log_error("Receive was interrupted. [error: %s]", strerror(errno));
                    continue;
                } else {
                    log_error("Receive returned and error. [error: %s]", strerror(errno));
                    return read_bytes;
                }
            }
        }
    }
}

int main(int argc, char **argv) {

    struct arguments arguments = {
            .payload = "",
            .flood = false,
            .log_level = 3,
            .log_file = "",
            .interface = "",
            .poll_timeout_msec = 100,
            .discovery_bcast_interval_msec = 100,
            .pending_timeout_msec = 100,
            .source_retransmit_payload_msec = 100,
            .unchanged_counter = 5,
            .tx_pwr_threshold = 0,
            .omit_roll_back = false,
    };
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    flood = arguments.flood;
    pending_timeout_msec = arguments.pending_timeout_msec;
    source_retransmit_payload_msec = arguments.source_retransmit_payload_msec;
    unchanged_counter = arguments.unchanged_counter;
    tx_pwr_threshold = arguments.tx_pwr_threshold;

    // Logging stuff
    if (arguments.log_level == 0) {
        log_set_quiet(true);
    } else {
        log_set_level(arguments.log_level - 1);
    }

    if (arguments.log_file[0] != '\0') {
        FILE *lf = fopen(arguments.log_file, "a");
        log_add_fp(lf, arguments.log_level - 1);
    }

    signal(SIGINT, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGABRT, sig_handler);
    signal(SIGSEGV, sig_handler);

    log_debug(
            "Initialized program. ["
            "payload_path: %s, "
            "max_power: %s, "
            "log_level: %i, "
            "log_file: %s, "
            "poll_timeout: %hu, "
            "discovery_timeout: %hu, "
            "pending_timeout: %hu, "
            "retransmit_timeout: %hu, "
            "unchanged_counter: %hu, "
            "tx_pwr_threshold: %hu, "
            "omit_roll_back: %s, "
            "interface: %s]",
            strnlen(arguments.payload, PATH_MAX) == 0 ? "-" : arguments.payload,
            arguments.flood ? "true" : "false",
            arguments.log_level,
            strnlen(arguments.log_file, PATH_MAX) == 0 ? "-" : arguments.log_file,
            arguments.poll_timeout_msec,
            arguments.discovery_bcast_interval_msec,
            arguments.pending_timeout_msec,
            arguments.source_retransmit_payload_msec,
            arguments.unchanged_counter,
            arguments.tx_pwr_threshold,
            arguments.omit_roll_back ? "true" : "false",
            arguments.interface
    );

    int sockfd = init_sock(arguments.interface, arguments.payload);
    if (sockfd < 0) {
        exit(sockfd);
    }

    if (strnlen(arguments.payload, PATH_MAX) != 0 && !flood) {
        broadcast_discovery();
    }

    int res = event_loop(arguments.poll_timeout_msec, arguments.discovery_bcast_interval_msec,
                         arguments.omit_roll_back);

    if (res == 0) {
        log_info("Gracefully exiting.");
    }

    return res;
}
