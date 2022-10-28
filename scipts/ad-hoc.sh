#! /bin/bash

set -Eeuox pipefail

# Get some base variables required for the setup
IFNAME="$(grep -l b8:27 /sys/class/net/wlan*/address | cut -d'/' -f5)"
MAC_ADDRESS="$(cat /sys/class/net/$IFNAME/address)"

FST=$(echo "$MAC_ADDRESS" | cut -d':' -f4 | tr -d '[:space:]')
SND=$(echo "$MAC_ADDRESS" | cut -d':' -f5 | tr -d '[:space:]')
TRD=$(echo "$MAC_ADDRESS" | cut -d':' -f6 | tr -d '[:space:]')
HNAME="btp-${FST}-${SND}-${TRD}"
IP_ADDR="10.$(( 16#$FST )).$(( 16#$SND )).$(( 16#$TRD ))"

# Setup ad-hoc mode
ifconfig "$IFNAME" down
iwconfig "$IFNAME" key off
iwconfig "$IFNAME" mode ad-hoc
ifconfig "$IFNAME" up
iwconfig "$IFNAME" essid btp
iwconfig "$IFNAME" channel 1
iwconfig "$IFNAME" ap c0:ff:ee:c0:ff:ee
ifconfig "$IFNAME" "$IP_ADDR"
ifconfig "$IFNAME" netmask 255.0.0.0
