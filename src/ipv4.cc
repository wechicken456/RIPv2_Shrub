#include "ipv4.h"
#include "tcp.h"
#include "udp.h"

/* return an integer indicating the length of the IPv4 packet (including encapsulated packets).
 * Note that this function only allocates the IPv4 header, and not the encapsulated packets. The rest of the packet lives in the iov array.
 * So this return value doesn't indicate the BUFFER size (iov_len) of the IPv4 header at iov[iov_idx], but the logical size of the entire packet, if it was contiguous.
 * This implementation is necessary in case the lower layer protocols (e.g. Ethernet) need the IPv4 packet size.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY IPv4 header will be written. 
 */
int process_ipv4(unsigned char *in_packet, int iov_idx) {
    struct ipv4_hdr *hdr = (struct ipv4_hdr *)in_packet;
    unsigned int ipv4_hdr_len = (hdr->version_ihl & 0b1111) << 2;

    
    /* if not meant for us, discard it */
    if (ntohl(*(uint32_t*)&hdr->dst_addr) != my_ipv4_addr) {
        printf("process_ipv4: Not for us...\n");
        return 0;
    }

    // verify IPv4 checksum
    if (verify_cksum(hdr, ipv4_hdr_len)) {   // S + ~S === 0
        fprintf(stderr, "[!] INVALID IPv4 CHECKSUM.\n");
        return -1;
    }

    // convert all the fields to host byte order
    hdr->hdr_checksum = ntohs(hdr->hdr_checksum);
    hdr->fragment_offset = ntohs(hdr->fragment_offset);
    hdr->frame_ident = ntohs(hdr->frame_ident); 
    hdr->total_len = ntohs(hdr->total_len);

    // uint8_t *src_addr = (uint8_t *)&(hdr->src_addr);
    // uint8_t *dst_addr = (uint8_t *)&(hdr->dst_addr);
    // printf("\tIP:	Vers:	%u\n", (hdr->version_ihl >> 4));
    // printf("\t\tHlen:	%u bytes\n", ipv4_hdr_len);
    // printf("\t\tSrc:\t%d.%d.%d.%d\t", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
    // if (resolveDNS) print_hostname(src_addr);
    // puts("");
    // printf("\t\tDest:\t%d.%d.%d.%d\t", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
    // if (resolveDNS) print_hostname(dst_addr);
    // puts("");
    // printf("\t\tTTL:\t%u\n", hdr->time_to_live);
    // printf("\t\tFrag Ident:\t%u\n", hdr->frame_ident);
    // printf("\t\tFrag Offset:\t%u\n", (hdr->fragment_offset & 0b1111111111111) << 3);
    // printf("\t\tFrag DF:\t%s\n", ((hdr->fragment_offset >> 13) & 0b010) ? "yes" : "no");
    // printf("\t\tFrag MF:\t%s\n", ((hdr->fragment_offset >> 13) & 0b001) ? "yes" : "no");
    // printf("\t\tIP CSum:\t%u\n", hdr->hdr_checksum);
    // printf("\t\tType:\t0x%x\t", hdr->next_proto_id);
    
    
    struct ipv4_hdr *reply_iph = NULL;
    int reply_iph_size;
    int ret; 
    //int ret;  
    switch (hdr->next_proto_id) {
        case IPV4_TYPE_TCP:
            printf("(TCP)\n");
            process_tcp((struct tcp_hdr *)(hdr + ipv4_hdr_len)); 
            break;
        case IPV4_TYPE_UDP:
            printf("(UDP)\n");
            ret = process_udp(in_packet + ipv4_hdr_len, (uint16_t*)hdr->src_addr, (uint16_t*)hdr->dst_addr, hdr->total_len - ipv4_hdr_len, iov_idx + 1); 
            if (ret < 0) {
                return ret;
            }
            
            // allocate buffer for the IPv4 header. 
            reply_iph_size = sizeof(struct ipv4_hdr);
            reply_iph = (struct ipv4_hdr *)malloc(reply_iph_size);
            if (reply_iph == NULL) {
                perror("malloc");
                return -1;
            }
            reply_iph->version_ihl = hdr->version_ihl;                               // Same header length 
            reply_iph->type_of_service = hdr->type_of_service;                       // Copy ToS
            reply_iph->total_len = htons(reply_iph_size + ret);                      // Total length = IPv4 header + UDP datagram   
            reply_iph->frame_ident = htons(hdr->frame_ident + 1);                    // ID can be whatever 
            reply_iph->fragment_offset = 0;                                       
            reply_iph->time_to_live = 64;                                               // random TTL 
            reply_iph->next_proto_id = IPPROTO_UDP;                                    // UDP 
            memcpy(&reply_iph->src_addr, hdr->dst_addr, 4);                          // Swap src and dst addresses
            memcpy(&reply_iph->dst_addr, hdr->src_addr, 4);
            
            // checksum is computed over ONLY the header as per RFC 791
            reply_iph->hdr_checksum = in_cksum((unsigned short *)reply_iph, sizeof(*reply_iph), 0);
            
            iov[iov_idx].iov_base = (unsigned char*)reply_iph;
            iov[iov_idx].iov_len = reply_iph_size;     
            iov_cnt++; 
            return reply_iph_size;

        case IPV4_TYPE_ICMP:
            printf("(ICMP)\n");

            // construct an ICMP packet
            ret = process_icmp(in_packet + ipv4_hdr_len, hdr->total_len - ipv4_hdr_len, iov_idx + 1);
            if (ret < 0) {  
                return ret;
            }

            // allocate buffer for the IPv4 header. 
            reply_iph_size = sizeof(struct ipv4_hdr);
            reply_iph = (struct ipv4_hdr *)malloc(reply_iph_size);
            if (reply_iph == NULL) {
                perror("malloc");
                return -1;
            }
            reply_iph->version_ihl = hdr->version_ihl;                               // Same header length 
            reply_iph->type_of_service = hdr->type_of_service;                       // Copy ToS
            reply_iph->total_len = htons(reply_iph_size + ret);                         // Total length = IPv4 header + ICMP packet   
            reply_iph->frame_ident = htons(hdr->frame_ident + 1);                    // ID can be whatever 
            reply_iph->fragment_offset = 0;                                       
            reply_iph->time_to_live = 64;                                               // random TTL 
            reply_iph->next_proto_id = IPPROTO_ICMP;                                    // ICMP 
            memcpy(&reply_iph->src_addr, hdr->dst_addr, 4);                          // Swap src and dst addresses
            memcpy(&reply_iph->dst_addr, hdr->src_addr, 4);
            
            // checksum is computed over ONLY the header as per RFC 791
            reply_iph->hdr_checksum = in_cksum((unsigned short *)reply_iph, sizeof(*reply_iph), 0);
            
            iov[iov_idx].iov_base = (unsigned char*)reply_iph;
            iov[iov_idx].iov_len = reply_iph_size;     
            iov_cnt++; 
            return reply_iph_size;

        default:
            puts("");
            break;
    } 
    return -1;
}