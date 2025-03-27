#!/bin/bash

## External interface name to use
## NOTE: will not work if your default interface has spaces in its name.
## if that is the case, either manually define this value, or enable taking the value as an argument.
EXT_IFACE_NAME="$(ip r | sed -n -E 's/^.*default.*dev ([^ ]*) .*$/\1/p')"
# EXT_IFACE_NAME="$1"

## Network to use, with interface address embedded.
## NOTE: If this interferes with some network you are a part of, change the value manually or
## enable taking the value as an argument.
IFACE_SPEC="172.31.128.1_24"
# IFACE_SPEC="$2"

## change to the standard CIDR notation (using a / as a separator between the address and prefix length)
NETRANGE="$(tr "_" "/" <<< ${IFACE_SPEC})"

## use ipcalc to make sure it is ipv4, get the address, the prefix length, the network name/address, and what category it is in
storage=$(ipcalc --addrspace  -4 -a -p -n "${NETRANGE}")

## only continue if the address range is not in the 'Internet' space (subset of all public addresses, just a minimal safety check)
if [ "$(echo "${storage}" | grep "ADDRSPACE")" = 'ADDRSPACE=Internet' ]; then
	echo "Not creating virtual interface for public IPs, may cause unexpected behavior..."
	exit -1 
fi

## extract the address, network name, and prefix from the ipcalc results.
ADDRESS="$(sed -E -n "s/ADDRESS=(.*)/\1/pg" - <<< "${storage}")"
NETWORK="$(sed -E -n "s/NETWORK=(.*)/\1/pg" - <<< "${storage}")"
PREFIX="$(sed -E -n "s/PREFIX=(.*)/\1/pg" - <<< "${storage}")"

## determine the pcap file name to use
PCAP_NAME="${NETWORK}_${PREFIX}.dmp"

## Determine the interface argument string (should be same as IFACE_SPEC)
IFACE_ARG="${ADDRESS}_${PREFIX}"

## make the pcap file
## NOTE: this overwrites any existing file of the same name.
./make_pcap.sh "${PCAP_NAME}"

## start the shim - this will take posession of the shell until you kill it.

sudo python3 shim.py -n "${IFACE_ARG}" -i "${EXT_IFACE_NAME}" # -d #(feel free to add -d to enable debugging output.)

exit 0

## -----------
## everything below this line is extra and just to show how to interact with the shim setup.

## assumes .2 is available on the network...
TWIG_ADDRESS="$(sed "s/(.*\..*\..*\.).*/2/g")"
## start the twig (same directory as this script was run in)
./twig -i "${TWIG_ADDRESS}_${PREFIX}"

## now we can ping or ask time or whatever from outside and our twig will reply (hopefully).
## e.g.
ping "${TWIG_ADDRESS}"
socket_time "${TWIG_ADDRESS}"