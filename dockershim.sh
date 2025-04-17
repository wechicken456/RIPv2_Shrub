#!/bin/bash

DIMGNAME="twigimage"
DNETNAME="twignet"
DNETCIDR="172.31.127.0/24"
DCONNAME="twigcontainer"
DCONADDR="172.31.127.254"
SHIMCIDR="172.31.0.0/16"

SHIMPCAP="172.31.128.0_24.dmp"

## if no docker image with the name we're lookng for, make one.
if [[ "$(docker images | grep \"${DIMGNAME}\" | wc -l)" -eq 0 ]] ; then
	echo "Building image '${DIMGNAME}'"
	docker build -t "${DIMGNAME}" .
fi


## if the docker network doesnt exist, make it.
if [[ "$(docker network list | grep \"${DNETNAME}\" | wc -l)" -eq 0 ]] ; then
	echo "Creating docker network '${DNETNAME}'"
	docker network create "--subnet=${DNETCIDR}" "${DNETNAME}"
fi

## make pcap so it doesnt get made as root.
./make_pcap.sh "${SHIMPCAP}"

## not doing ip routes here, those should be handled outside by the script running the twigs.
## (CHAIN.sh or BOWTIE.sh for example)

## now we start a container from the image
echo "Starting docker container with name ${DCONNAME} and ip ${DCONADDR}"
docker run --name "${DCONNAME}" --net "${DNETNAME}" --ip "${DCONADDR}" --mount type=bind,src=.,dst=/usr/local/twig --rm -it "${DIMGNAME}"

## no cleanup option, let the user deal with that.
## this is meant as a minimal script to allow easy reuse for multirouter setups.