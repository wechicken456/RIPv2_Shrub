#!/bin/bash

DIMGNAME="twigimage"
DNETNAME="twignet"
DNETCIDR="172.31.127.0/24"
DCONNAME="twigcontainer"
DCONADDR="172.31.127.254"
SHIMCIDR="172.31.0.0/16"

## if the first argument is --rm, then clean up the docker network and ip route when we're done.
cleanup="$1"

## build docker image from the dockerfile in this directory
echo "Building image '${DIMGNAME}'"
docker build -t "${DIMGNAME}" .

## make a docker network for our docker containers called `twignet`
echo "Making docker network '${DNETNAME}'"
docker network create "--subnet=${DNETCIDR}" "${DNETNAME}"

## add ip route for twig traffic, directing it via the docker container we're about to run.
echo "Adding ip route for shim traffic (${SHIMCIDR}) via ${DCONADDR}"
sudo ip route add "${SHIMCIDR}" via "${DCONADDR}"

## make pcap so it doesnt get made as root.
./make_pcap.sh "${SHIMPCAP}"

## now we start a container from the image
echo "Starting docker container with name ${DCONNAME} and ip ${DCONADDR}"
docker run --name "${DCONNAME}" --net "${DNETNAME}" --ip "${DCONADDR}" --mount type=bind,src=.,dst=/usr/local/twig --rm -it "${DIMGNAME}"

if [[ "${cleanup}" == "--rm" ]]; then

echo "Removing container..."
## container is gone, we used `--rm`, just letting everyone know its gone

echo "Removing docker network..."
docker network remove "${DNETNAME}"

echo "Removing ip route for shim traffic..."
sudo ip route delete "${SHIMCIDR}"

fi