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

## Take -w as an argument and run wireshark if provided.
## this isnt a robust system, so it will require specific ordering if other arguments become supported...
RUN_WIRESHARK="${1}"

## change to the standard CIDR notation (using a / as a separator between the address and prefix length)
NETRANGE="$(tr "_" "/" <<< ${IFACE_SPEC})"

## REPLACE IPCALC WITH FOLLOWING
ADDRESS="$(awk -F_ '{printf $1}' <<< ${IFACE_SPEC})"
PREFIX="$(awk -F_ '{printf $2}' <<< ${IFACE_SPEC})"
## to get network, we just need to bitwise and each octet with the corresponding bits of the prefix.
## first, make a netmask from the prefix.

# echo "${ADDRESS}"
# echo "${PREFIX}"

PREFIX_COPY="${PREFIX}"

NETMASK=""
for i in {1..4}; do
	if (( PREFIX_COPY >= 8 )); then
		NETMASK="${NETMASK}255"
		(( PREFIX_COPY -= 8 ))

		if(( i != 4 )); then
			NETMASK="${NETMASK}."
		fi
	else
		NETMASK="${NETMASK}$(bc <<< '255 - (2^(8-'${PREFIX_COPY}') - 1)')"
		PREFIX_COPY=0
		if(( i != 4 )); then
			NETMASK="${NETMASK}."
		fi
	fi
done

# echo "${NETMASK}"

NETWORK=""
## now use the netmask to calculate the network name
for i in {1..4}; do
	NETWORK="${NETWORK}$(( $(awk -F. '{print $'${i}'}' <<< "${NETMASK}") & $(awk -F. '{print $'${i}'}' <<< "${ADDRESS}")  ))"
	if(( i != 4 )); then
		NETWORK="${NETWORK}."
	fi
done


# echo "${NETWORK}"

## determine the pcap file name to use
PCAP_NAME="${NETWORK}_${PREFIX}.dmp"

## Determine the interface argument string (should be same as IFACE_SPEC)
IFACE_ARG="${ADDRESS}_${PREFIX}"

# echo "${PCAP_NAME}"
# echo "${IFACE_ARG}"
# exit 0

## make the pcap file
## NOTE: this overwrites any existing file of the same name.
./make_pcap.sh "${PCAP_NAME}"

## start a tail-powered wireshark capture if requested
if [ "${RUN_WIRESHARK}" = "-w" ]; then
	echo "starting wireshark"
	tail -f -c +0 "${PCAP_NAME}" | wireshark -k -i - 1>&2 2>/dev/null &
fi

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