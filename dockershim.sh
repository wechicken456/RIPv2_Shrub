#!/bin/bash

DIMGNAME="twigimage"
DNETNAME="twignet"
DCONNAME="twigcontainer"
DCONADDR="172.31.127.254"

## now we start a container from the image
echo "Starting docker container with name ${DCONNAME} and ip ${DCONADDR}"
docker run --name "${DCONNAME}" --net "${DNETNAME}" --ip "${DCONADDR}" --mount type=bind,src=.,dst=/usr/local/twig --rm -it "${DIMGNAME}"
