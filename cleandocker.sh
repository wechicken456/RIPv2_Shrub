DIMGNAME="twigimage"
DNETNAME="twignet"
DNETCIDR="172.31.127.0/24"
DCONNAME="twigcontainer"
DCONADDR="172.31.127.254"
SHIMCIDR="172.31.0.0/16"

echo "Removing docker network '${DNETNAME}'"
docker network remove "${DNETNAME}"

## no container removal since everywhere we run a container we use --rm
## the image removal will complain if the user has some containers still around using the image.

echo "Removing docker image '${DIMGNAME}'"
docker image rm "${DIMGNAME}"
