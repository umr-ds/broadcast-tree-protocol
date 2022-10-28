# Broadcast Tree Protocol

This repository contains the userland implementation of the energy-efficient broadcast tree protocol (BTP).

## Requirements
This protocol needs [RadioTap](https://www.radiotap.org) headers to work, as it is relying on the RSSI and SNR of a received frame.
Therefore, it is only working on Raspberry Pi 3B with the Wi-Fi firmware patch installed found in `nexmon_patch`.
Please follow the [official instructions](https://nexmon.org) to install the patch.

## Build
We provide a simple Makefile for building the binary.

## Usage
```
Usage: btp [OPTION...] INTERFACE
BTP -- Broadcast Tree Protocol

  -d, --flood                Whether to use simple flooding protocol or BTP
  -s, --source=payload       Path to the payload to be sent (omit this option
                             for client mode)
  -b, --broadcast_timeout=msec   How often the discovery frames should be
                             broadcasted
  -f, --log_file=path        File path to log file.
                             If not present only stdout and stderr logging will
                             be used
  -l, --log_level=level      Log level
                             0: QUIET, 1: TRACE, 2: DEBUG, 3: INFO (default),
                             4: WARN, 5: ERROR, 6: FATAL
  -o, --omit_roll_back       Do not roll back tree after payload is completely
                             received
  -p, --poll_timeout=msec    Timeout for poll syscall
  -r, --retransmit_timeout=msec   How long to wait for retransmitting the
                             payload from the source
  -t, --pending_timeout=msec How long to wait for potential parent to answer
  -u, --unchanged_counter=number   How many rounds to wait until declaring game
                             finished
  -x, --tx_pwr_threshold=thresh   Add threshold to avoid setting tx power too
                             low
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.

Report bugs to <sterz@mathematik.uni-marburg.de>.
```
