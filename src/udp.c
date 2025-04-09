#include "udp.h"

void print_udp(struct udp_hdr *udp_datagram) {
    reverse_assign(&(udp_datagram->src_port), sizeof(udp_datagram->src_port));
    reverse_assign(&(udp_datagram->dst_port), sizeof(udp_datagram->dst_port));
    reverse_assign(&(udp_datagram->len), sizeof(udp_datagram->len));
    reverse_assign(&(udp_datagram->cksum), sizeof(udp_datagram->cksum));

    printf("\tUDP:\tSport:\t%u\n", *(uint16_t*)udp_datagram->src_port);
    printf("\t\tDport:\t%u\n", *(uint16_t*)udp_datagram->dst_port);
    printf("\t\tDGlen:\t%u\n", *(uint16_t*)udp_datagram->len);
    printf("\t\tCSum:\t%u\n", *(uint16_t*)udp_datagram->cksum);
}

void process_udp(struct udp_hdr *udp_datagram) {
    print_udp(udp_datagram);
}



