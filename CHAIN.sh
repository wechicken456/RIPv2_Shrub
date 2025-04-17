#!/bin/sh

TOOLDIR=.
PROGRAM="shrub" ## allow specifying a different name for shub program.

#
# enable debugging if requested
#DEBUG="-d -d"
#DEBUG="-d"
DEBUG=""

RIP_INTERVAL_ARG="-r 1"


## ARGUMENT PARSING
for i in "$@"; do
	case $i in
		-d=*|--docker=*)
			DOCKERIP="${i#*=}"
			shift # past argument=value
			;;
		--dry-run)
			DRYRUN="YES"
			shift # past argument with no value
			;;
		-h|--help)
			cat <<EOF
Usage: $0 [options]

-h| --help          Display this help message and exit
-d|--docker=<shim-docker-container-ip>  Set the ip for a docker container running the shim. This mode also enables the automatic creation of ip route rules on the local machine, and may prompt for root access to set those ip rules. 
--dry-run			Run the script without executing commands, and instead printing them out.
EOF
			exit 0 
			;;
		-*|--*)
			echo "Unknown option $i"
			exit 1
			;;
		*)
			;;
	esac
done


SHIM_MAX_SUBNET="172.31.0.0"
SHIM_MAX_MASK=16

SHIM_PREFIX="172.31.128" ## network the shim uses as its file interface.

INTERNAL_PREFIX="172.31"
INTERNAL_PREFIX1="${INTERNAL_PREFIX}.1"
INTERNAL_PREFIX2="${INTERNAL_PREFIX}.2"
INTERNAL_PREFIX3="${INTERNAL_PREFIX}.3"
INTERNAL_PREFIX4="${INTERNAL_PREFIX}.4"
INTERNAL_PREFIX5="${INTERNAL_PREFIX}.5"
## not using publics since we need 
## routing to them and dont want 
## to mess with real routes if possible.
MASKS=24

#

## shim attaches to 172.31.1.0/24
# ./shrub [-d] -r 1 -i 172.31.128.254_24 -i 172.31.1.253_24 --default-route 172.31.128.254_24
# ./shrub [-d] -r 1 -i 172.31.1.254_24   -i 172.31.2.253_24
# ./shrub [-d] -r 1 -i 172.31.2.254_24   -i 172.31.3.253_24
# ./shrub [-d] -r 1 -i 172.31.3.254_24   -i 172.31.4.253_24
# ./shrub [-d] -r 1 -i 172.31.4.254_24   -i 172.31.5.253_24
# ./shrub [-d] -r 1 -i 172.31.5.254_24
## chain ends with a shrub with only one interface.



## wont work for masks that arent /24...
PCAP_NAME_SHIM="${SHIM_PREFIX}.0_${MASKS}.dmp"
PCAP_NAME_1="${INTERNAL_PREFIX1}.0_${MASKS}.dmp"
PCAP_NAME_2="${INTERNAL_PREFIX2}.0_${MASKS}.dmp"
PCAP_NAME_3="${INTERNAL_PREFIX3}.0_${MASKS}.dmp"
PCAP_NAME_4="${INTERNAL_PREFIX4}.0_${MASKS}.dmp"
PCAP_NAME_5="${INTERNAL_PREFIX5}.0_${MASKS}.dmp"

## make pcaps, overwrites old pcaps.
if [[ -z "${DRYRUN}" ]]; then
	echo "Making pcaps"
	./make_pcap.sh "${PCAP_NAME_SHIM}"

	# cleanup old packet files
	# rm -f ${INTERNAL_PREFIX}*.dmp
	rm ${PCAP_NAME_1} ${PCAP_NAME_2} ${PCAP_NAME_3} ${PCAP_NAME_4} ${PCAP_NAME_5}

	if [[ -n "${DOCKERIP}" ]]; then
		echo "Adding IP route to docker container located at ip ${DOCKERIP}"
		sudo ip route add "${SHIM_MAX_SUBNET}/${SHIM_MAX_MASK}" via "${DOCKERIP}"
	fi
else
	echo "Printing commands which would be run:"
	echo "./make_pcap.sh ${PCAP_NAME_SHIM}"

	echo "rm -f ${PCAP_NAME_1} ${PCAP_NAME_2} ${PCAP_NAME_3} ${PCAP_NAME_4} ${PCAP_NAME_5}"

	if [[ -n "${DOCKERIP}" ]]; then
		echo "Printing commands which would run to add IP routes to docker container located at ip ${DOCKERIP}"
		echo "sudo ip route add ${SHIM_MAX_SUBNET}/${SHIM_MAX_MASK} via ${DOCKERIP}"
	fi
fi


#
# all of the router addresses
# ./shrub [-d] -r 1 -i 172.31.128.254_24 -i 172.31.1.253_24
ROUTER_SHIM_IN="${SHIM_PREFIX}.254_${MASKS}"
ROUTER_SHIM_OUT="${INTERNAL_PREFIX1}.253_${MASKS}"
# ./shrub [-d] -r 1 -i 172.31.1.254_24   -i 172.31.2.253_24
ROUTER_1_IN="${INTERNAL_PREFIX1}.254_${MASKS}"
ROUTER_1_OUT="${INTERNAL_PREFIX2}.253_${MASKS}"
# ./shrub [-d] -r 1 -i 172.31.2.254_24   -i 172.31.3.253_24
ROUTER_2_IN="${INTERNAL_PREFIX2}.254_${MASKS}"
ROUTER_2_OUT="${INTERNAL_PREFIX3}.253_${MASKS}"
# ./shrub [-d] -r 1 -i 172.31.3.254_24   -i 172.31.4.253_24
ROUTER_3_IN="${INTERNAL_PREFIX3}.254_${MASKS}"
ROUTER_3_OUT="${INTERNAL_PREFIX4}.253_${MASKS}"
# ./shrub [-d] -r 1 -i 172.31.4.254_24   -i 172.31.5.253_24
ROUTER_4_IN="${INTERNAL_PREFIX4}.254_${MASKS}"
ROUTER_4_OUT="${INTERNAL_PREFIX5}.253_${MASKS}"
# ./shrub [-d] -r 1 -i 172.31.5.254_24
ROUTER_5_IN="${INTERNAL_PREFIX5}.254_${MASKS}"
#
# UDPPing Client - inside
# UDPPING_CLIENT="${INTERNAL_PREFIX}.1_${MASKS}"
# UDPPING_SERVER_ADDR="${PUBLIC_PREFIX}.254"
#
# Make the router chain
CMDS1="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_SHIM_IN} -i ${ROUTER_SHIM_OUT} --default-route ${ROUTER_SHIM_IN}"
CMDS2="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_1_IN}    -i ${ROUTER_1_OUT}"
CMDS3="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_2_IN}    -i ${ROUTER_2_OUT}"
CMDS4="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_3_IN}    -i ${ROUTER_3_OUT}"
CMDS5="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_4_IN}    -i ${ROUTER_4_OUT}"
CMDS6="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_5_IN}"
#
if [[ -z "${DRYRUN}" ]]; then
	echo "Starting routers";
else
	echo "Printing commands which would have been run:"
fi
echo ${CMDS1}
echo ${CMDS2}
echo ${CMDS3}
echo ${CMDS4}
echo ${CMDS5}
echo ${CMDS6}
# bash # start a new shell session, so can type 'exit' to kill the shrubs.

## 
if [[ -z "${DRYRUN}" ]]; then
	${CMDS1} & ${CMDS2} & ${CMDS3} & ${CMDS4} & ${CMDS5} & ${CMDS6} &
	echo "Kill the network by typing:	ps | grep '${PROGRAM}' | awk '{ print \$1 }' | xargs kill"
fi
#
# CMDC="${TOOLDIR}/udpping -p 5  ${DEBUG} -i ${UDPPING_CLIENT} ${UDPPING_SERVER_ADDR}"
CMDD="traceroute ${INTERNAL_PREFIX4}.254"
# echo "Start UDPping client by typing:   ${CMDC}"
echo "Traceroute to router 4 with:   ${CMDD}"

CMDD="ping ${INTERNAL_PREFIX4}.254"
echo "ping router 4 with:   ${CMDD}"

# bash
# ps | grep "${PROGRAM}" | awk '{ print $1 }' | xargs kill



