#!/bin/sh
TOOLDIR=.
PROGRAM="shrub" ## allow specifying a different name for shub program.

#
# enable debugging if requested
# DEBUG="-d -d"
# DEBUG="-d"
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

# the ring
BOWTIE_PREFIX="172.31"
BOWTIE_PREFIX1=${BOWTIE_PREFIX}.1
BOWTIE_PREFIX2=${BOWTIE_PREFIX}.2
BOWTIE_PREFIX3=${BOWTIE_PREFIX}.3
BOWTIE_PREFIX4=${BOWTIE_PREFIX}.4
BOWTIE_PREFIX5=${BOWTIE_PREFIX}.5
# the bowtie at the bottom
BOWTIE_PREFIX6=${BOWTIE_PREFIX}.6
# BOWTIE_PREFIX7=${BOWTIE_PREFIX}.7
BOWTIE_PREFIX7=${BOWTIE_PREFIX}.128

BOWTIE_PREFIX8=${BOWTIE_PREFIX}.8
MASKS=24
#
# cleanup old packet files

PCAP_NAME_SHIM="${BOWTIE_PREFIX7}.0_${MASKS}.dmp"

## make pcaps, overwrites old pcaps.
if [[ -z "${DRYRUN}" ]]; then
	echo "Making pcaps"

  ./make_pcap.sh "${PCAP_NAME_SHIM}"
	# cleanup old packet files
  rm -f ${BOWTIE_PREFIX}.?.*.dmp

	if [[ -n "${DOCKERIP}" ]]; then
		echo "Adding IP route to docker container located at ip ${DOCKERIP}"
		sudo ip route add "${SHIM_MAX_SUBNET}/${SHIM_MAX_MASK}" via "${DOCKERIP}"
	fi
else
	echo "Printing commands which would be run:"
	echo "./make_pcap.sh ${PCAP_NAME_SHIM}"

	echo "rm -f ${BOWTIE_PREFIX}.?.*.dmp"

	if [[ -n "${DOCKERIP}" ]]; then
		echo "Printing commands which would run to add IP routes to docker container located at ip ${DOCKERIP}"
		echo "sudo ip route add ${SHIM_MAX_SUBNET}/${SHIM_MAX_MASK} via ${DOCKERIP}"
	fi
fi

#
# all of the router addresses - ring
ROUTER_P_1="${BOWTIE_PREFIX5}.201_${MASKS}"
ROUTER_P_2="${BOWTIE_PREFIX1}.201_${MASKS}"

ROUTER_Q_1="${BOWTIE_PREFIX1}.202_${MASKS}"
ROUTER_Q_2="${BOWTIE_PREFIX2}.202_${MASKS}"

ROUTER_R_1="${BOWTIE_PREFIX2}.203_${MASKS}"
ROUTER_R_2="${BOWTIE_PREFIX3}.203_${MASKS}"

ROUTER_T_1="${BOWTIE_PREFIX4}.205_${MASKS}"
ROUTER_T_2="${BOWTIE_PREFIX5}.205_${MASKS}"
# connector
ROUTER_S_1="${BOWTIE_PREFIX3}.204_${MASKS}"
ROUTER_S_2="${BOWTIE_PREFIX4}.204_${MASKS}"
ROUTER_S_3="${BOWTIE_PREFIX8}.204_${MASKS}"
# bowtie
ROUTER_U_1="${BOWTIE_PREFIX7}.206_${MASKS}"
ROUTER_U_2="${BOWTIE_PREFIX8}.206_${MASKS}"

ROUTER_V_1="${BOWTIE_PREFIX6}.207_${MASKS}"
ROUTER_V_2="${BOWTIE_PREFIX8}.207_${MASKS}"

# Make the ring routers
CMDS1="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_P_1} -i ${ROUTER_P_2}"
CMDS2="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_Q_1} -i ${ROUTER_Q_2}"
CMDS3="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_R_1} -i ${ROUTER_R_2}"
CMDS4="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_S_1} -i ${ROUTER_S_2} -i ${ROUTER_S_3}"
CMDS5="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_T_1} -i ${ROUTER_T_2}"
# bowtie routers
CMDS6="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_U_1} -i ${ROUTER_U_2} --default-route ${ROUTER_U_1}"
CMDS7="${TOOLDIR}/${PROGRAM} ${DEBUG} ${RIP_INTERVAL_ARG} -i ${ROUTER_V_1} -i ${ROUTER_V_2}"
#
echo "Starting routers";
echo ${CMDS1}
echo ${CMDS2}
echo ${CMDS3}
echo ${CMDS4}
echo ${CMDS5}
echo ${CMDS6}
echo ${CMDS7}
# uncomment to actually start them
if [[ -z "${DRYRUN}" ]]; then
  ${CMDS1} & ${CMDS2} & ${CMDS3} & ${CMDS4} & ${CMDS5} & ${CMDS6} & ${CMDS7} &
	echo "Kill the network by typing:	ps | grep '${PROGRAM}' | awk '{ print \$1 }' | xargs kill"
fi
#

# ROUTER_U_1="${BOWTIE_PREFIX7}.206_${MASKS}"
# ROUTER_U_2="${BOWTIE_PREFIX8}.206_${MASKS}"
echo "ping router U with: ping ${BOWTIE_PREFIX7}.206"

# ROUTER_S_1="${BOWTIE_PREFIX3}.204_${MASKS}"
# ROUTER_S_2="${BOWTIE_PREFIX4}.204_${MASKS}"
# ROUTER_S_3="${BOWTIE_PREFIX8}.204_${MASKS}"
echo "ping router S with: ping ${BOWTIE_PREFIX8}.204"

# ROUTER_V_1="${BOWTIE_PREFIX6}.207_${MASKS}"
# ROUTER_V_2="${BOWTIE_PREFIX8}.207_${MASKS}"
echo "ping router V with: ping ${BOWTIE_PREFIX8}.207"

# ROUTER_R_1="${BOWTIE_PREFIX2}.203_${MASKS}"
# ROUTER_R_2="${BOWTIE_PREFIX3}.203_${MASKS}"
echo "ping router R with: ping ${BOWTIE_PREFIX3}.203"

# ROUTER_T_1="${BOWTIE_PREFIX4}.205_${MASKS}"
# ROUTER_T_2="${BOWTIE_PREFIX5}.205_${MASKS}"
echo "ping router T with: ping ${BOWTIE_PREFIX4}.205"

# ROUTER_P_1="${BOWTIE_PREFIX5}.201_${MASKS}"
# ROUTER_P_2="${BOWTIE_PREFIX1}.201_${MASKS}"
echo "ping router P with: ping ${BOWTIE_PREFIX5}.201"

# ROUTER_Q_1="${BOWTIE_PREFIX1}.202_${MASKS}"
# ROUTER_Q_2="${BOWTIE_PREFIX2}.202_${MASKS}"
echo "ping router Q with: ping ${BOWTIE_PREFIX2}.202"

CMDD="traceroute ${BOWTIE_PREFIX5}.201"
echo "Traceroute to router P with:   ${CMDD}"

CMDD="traceroute ${BOWTIE_PREFIX8}.207"
echo "Traceroute to router V with:   ${CMDD}"

#
# echo "Type to start a machine G:  ./${PROGRAM} -i ${BOWTIE_PREFIX6}.1_${MASKS}"
# echo "Type to start a machine H:  ./${PROGRAM} -i ${BOWTIE_PREFIX7}.2_${MASKS}"
# echo "Type to start a machine B:  ./${PROGRAM} -i ${BOWTIE_PREFIX1}.3_${MASKS}"



