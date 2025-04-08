#include "ipv4.h"
#include "tcp.h"
#include "udp.h"

unsigned char* process_ipv4(struct ipv4_hdr *ipv4_packet, int *reply_pkt_size) {
    unsigned int ipv4_hdr_len = (ipv4_packet->version_ihl & 0b1111) << 2;
    uint8_t *src_addr = (uint8_t *)&(ipv4_packet->src_addr);
    uint8_t *dst_addr = (uint8_t *)&(ipv4_packet->dst_addr);
    
    // verify IPv4 checksum
    if (verify_cksum(ipv4_packet, ipv4_hdr_len)) {   // S + ~S === 0
        fprintf(stderr, "[!] INVALID IPv4 CHECKSUM.\n");
        return NULL;
    }

    ipv4_packet->hdr_checksum = ntohs(ipv4_packet->hdr_checksum);
    ipv4_packet->fragment_offset = ntohs(ipv4_packet->fragment_offset);
    ipv4_packet->frame_ident = ntohs(ipv4_packet->frame_ident); 

    printf("\tIP:	Vers:	%u\n", (ipv4_packet->version_ihl >> 4));
    printf("\t\tHlen:	%u bytes\n", ipv4_hdr_len);
    printf("\t\tSrc:\t%d.%d.%d.%d\t", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
    if (resolveDNS) print_hostname(src_addr);
    puts("");
    printf("\t\tDest:\t%d.%d.%d.%d\t", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
    if (resolveDNS) print_hostname(dst_addr);
    puts("");
    printf("\t\tTTL:\t%u\n", ipv4_packet->time_to_live);
    printf("\t\tFrag Ident:\t%u\n", ipv4_packet->frame_ident);
    printf("\t\tFrag Offset:\t%u\n", (ipv4_packet->fragment_offset & 0b1111111111111) << 3);
    printf("\t\tFrag DF:\t%s\n", ((ipv4_packet->fragment_offset >> 13) & 0b010) ? "yes" : "no");
    printf("\t\tFrag MF:\t%s\n", ((ipv4_packet->fragment_offset >> 13) & 0b001) ? "yes" : "no");
    printf("\t\tIP CSum:\t%u\n", ipv4_packet->hdr_checksum);
    printf("\t\tType:\t0x%x\t", ipv4_packet->next_proto_id);
    
    
    unsigned char *reply_packet = NULL;
    int reply_packet_size;
    struct ipv4_hdr *reply_iph;
    unsigned char *data = NULL;  
    //int ret;  
    switch (ipv4_packet->next_proto_id) {
        case IPV4_TYPE_TCP:
            printf("(TCP)\n");
            process_tcp((struct tcp_hdr *)((char*)ipv4_packet + ipv4_hdr_len)); 
            break;
        case IPV4_TYPE_UDP:
            printf("(UDP)\n");
            process_udp((struct udp_hdr *)((char*)ipv4_packet + ipv4_hdr_len)); 
            break;
        case IPV4_TYPE_ICMP:
            printf("(ICMP)\n");

            // construct an ICMP packet
            int reply_icmp_size = 0;
            data = process_icmp((struct icmp_hdr *)((unsigned char*)ipv4_packet + ipv4_hdr_len), 
                                        ntohs(ipv4_packet->total_len) - ipv4_hdr_len, &reply_icmp_size);
            if (data == NULL) {  // NULL for failed
                return NULL;
            }

            // allocate buffer for the IPv4 + ICMP. 
            reply_packet_size = sizeof(struct ipv4_hdr) + reply_icmp_size;
            reply_packet = (unsigned char *)malloc(reply_packet_size);
            if (reply_packet == NULL) {
                perror("malloc");
                return NULL;
            }
            reply_iph = (struct ipv4_hdr *)reply_packet;
            reply_iph->version_ihl = ipv4_packet->version_ihl;                          // Same header length 
            reply_iph->type_of_service = ipv4_packet->type_of_service;                  // Copy ToS
            reply_iph->total_len = htons(reply_packet_size);/* Total length */
            reply_iph->frame_ident = htons(ntohs(ipv4_packet->frame_ident) + 1);        // Increment ID 
            reply_iph->fragment_offset = 0;                                             // No fragmentation 
            reply_iph->time_to_live = 64;                                               // New TTL 
            reply_iph->next_proto_id = IPPROTO_ICMP;                                    // ICMP */
            memcpy(&reply_iph->src_addr, ipv4_packet->dst_addr, 4);                     // Swap src and dst addresses
            memcpy(&reply_iph->dst_addr, ipv4_packet->src_addr, 4);

            reply_iph->hdr_checksum = in_cksum((unsigned short *)reply_iph, ipv4_hdr_len, 0);
            // copy icmp packet into the data section of IPv4 packet
            memcpy((unsigned char*)(reply_packet + sizeof(struct ipv4_hdr)), data, reply_icmp_size); 
            // free the old buffer that was holding icmp packet struct
            *reply_pkt_size = reply_packet_size;
            free(data);       
        default:
            puts("");
            break;
    } 
    return reply_packet;
}