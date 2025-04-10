FROM ubuntu:noble


# install needed packages
RUN apt update
RUN apt install python3 pip iproute2 bc xxd sudo net-tools libpcap-dev -y
RUN pip install scapy netifaces --break-system-packages


# udpping port
EXPOSE 7/udp

# no user since we want root access for scapy

# run twig test to start
WORKDIR /usr/local/twig
CMD ["./twig_test.sh"]