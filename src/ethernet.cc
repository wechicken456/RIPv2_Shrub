#include "ethernet.h"

void print_ethernet(struct eth_hdr *peh) {
    unsigned char *c = (unsigned char*)&(peh->h_proto);
	printf("%02x:%02x:%02x:%02x:%02x:%02x	%02x:%02x:%02x:%02x:%02x:%02x	0x%02x%02x\n", 
        peh->h_dest[0], peh->h_dest[1], peh->h_dest[2],
        peh->h_dest[3], peh->h_dest[4], peh->h_dest[5],
        peh->h_source[0], peh->h_source[1], peh->h_source[2],
        peh->h_source[3], peh->h_source[4], peh->h_source[5], c[0], c[1]);
}

int process_arp(struct arp_ipv4_hdr *arp_frame) {
    reverse_assign(&(arp_frame->h_type), sizeof(arp_frame->h_type));
    reverse_assign(&(arp_frame->op), sizeof(arp_frame->op));

    printf("\tARP:\tHWtype:\t%u\n", *(uint16_t*)arp_frame->h_type);
    printf("\t\thlen:\t%u\n", arp_frame->hlen_plen[0]);
    printf("\t\tplen:\t%u\n", arp_frame->hlen_plen[1]);
    printf("\t\tOP:\t%u %s\n", *(uint16_t*)arp_frame->op, 
                            (*(uint16_t*)arp_frame->op == 1) ? "(ARP request)" : "(ARP reply)");

    printf("\t\tHardware:\t");
    print_addr_6(arp_frame->sha);
    puts("");
    printf("\t\t\t==>\t");
    print_addr_6(arp_frame->tha);
    puts("");

    printf("\t\tProtocol:\t");
    if (arp_frame->hlen_plen[1] == 4) print_addr_4(arp_frame->spa);
    else print_addr_6(arp_frame->spa);
    puts("\t");
    printf("\t\t\t==>\t");
    if (arp_frame->hlen_plen[1] == 4) print_addr_4(arp_frame->tpa);
    else print_addr_6(arp_frame->tpa);
    puts("\t");

    if (*(uint16_t*)arp_frame->op != 1) {   // ARP reply
        if (arp_frame->hlen_plen[1] == 4) arp_cache_v4[*(uint64_t*)arp_frame->sha] = *(uint32_t*)arp_frame->spa;  // both in key and val network byte order
        else arp_cache_v6[*(uint64_t*)arp_frame->sha] = *(uint64_t*)arp_frame->spa;  // both in key and val network byte order
    }
    return 0;
}


/* return an integer indicating the length of the Ethernet packet (including encapsulated packets): -1 for error, 0 if not for us, or the length of the packet if successful.
 * Note that this function only allocates the Ethernet header, and not the encapsulated packets. The rest of the packet lives in the iov array.
 * So this return value doesn't indicate the BUFFER size (iov_len) of the Ethernet header at iov[iov_idx], but the logical size of the entire packet, if it was contiguous.
 * This implementation is necessary in case the lower layer protocols (e.g. Ethernet) need the Ethernet packet size.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY Ethernet header will be written. 
 */
int process_ethernet(unsigned char *in_packet, int iov_idx) {
    print_ethernet((struct eth_hdr *) in_packet);

    int ret = -1;
    struct eth_hdr *orig_eth = (struct eth_hdr *)in_packet;
    struct eth_hdr *new_eth = NULL;
    orig_eth->h_proto = htons(orig_eth->h_proto);

    /*
    if (*(uint64_t*)orig_eth->h_source == interfaces[thread_interface_idx].mac_addr) {
        fprintf(stderr, "[!] Packet is from us. Ignoring...\n");
        return 0;
    }
    */
    switch (orig_eth->h_proto) { 
        case ETHERTYPE_IPV4: // IPv4 
            ret = process_ipv4(in_packet + sizeof(struct eth_hdr), iov_idx + 1);     // Ethernet is only above Pcap header, so hardcode 1
            if (ret <= 0) {
                if (debug) fprintf(stderr, "process_ipv4 returned with code %d\n", ret);
                return ret;
            }

            new_eth = (struct eth_hdr *)malloc(sizeof(struct eth_hdr));
            if (!new_eth) {
                perror("ethernet.cc: malloc: ");
                exit(1);
            }

            /* Hardcode source addresss's first 2 bytes to 5e:fe as per the testing instructions and how the shim.py works */
            memcpy(new_eth->h_dest, orig_eth->h_source, 6);
            memcpy(new_eth->h_source, interfaces[thread_interface_idx].mac_addr, 6);    
            new_eth->h_proto = htons(ETHERTYPE_IPV4);    

            iov[iov_idx].iov_base = new_eth;
            iov[iov_idx].iov_len = sizeof(struct eth_hdr);
            iov_cnt++;
            return ret + sizeof(struct eth_hdr);
        case ETHERTYPE_ARP:
            ret = process_arp((struct arp_ipv4_hdr *)(in_packet + sizeof(struct eth_hdr)));
            break;
        default:
            break;
    }
    return ret;
}
