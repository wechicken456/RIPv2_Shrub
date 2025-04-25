#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "rip.h"
#include "include.h"

/* return an integer indicating the length of the IPv4 packet (including encapsulated packets): -1 for error, 0 if not for us (the interface this thread is responsible for reading from), 
 * or the length of the packet if successful.
 * Note that this function only allocates the IPv4 header, and not the encapsulated packets. The rest of the packet lives in the iov array.
 * So this return value doesn't indicate the BUFFER size (iov_len) of the IPv4 header at iov[iov_idx], but the logical size of the entire packet, if it was contiguous.
 * This implementation is necessary in case the lower layer protocols (e.g. Ethernet) need the IPv4 packet size.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY IPv4 header will be written. 
 */
int process_ipv4(unsigned char *in_packet, int iov_idx) {
    struct ipv4_hdr *hdr = (struct ipv4_hdr *)in_packet;
    unsigned int ipv4_hdr_len = (hdr->version_ihl & 0b1111) << 2;
    
    if (debug >= 1) {
        printf("[+] Received an IPv4 packet.\n");
    }
    if (debug >= 2) {
        uint8_t *src_addr = (uint8_t *)&(hdr->src_addr);
        uint8_t *dst_addr = (uint8_t *)&(hdr->dst_addr);
        printf("\tIP:	Vers:	%u\n", (hdr->version_ihl >> 4));
        printf("\t\tHlen:	%u bytes\n", ipv4_hdr_len);
        printf("\t\tSrc:\t%d.%d.%d.%d\t", src_addr[0], src_addr[1], src_addr[2], src_addr[3]);
        if (resolveDNS) print_hostname(src_addr);
        puts("");
        printf("\t\tDest:\t%d.%d.%d.%d\t", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
        if (resolveDNS) print_hostname(dst_addr);
        puts("");
        printf("\t\tTTL:\t%u\n", hdr->time_to_live);
        printf("\t\tFrag Ident:\t%u\n", hdr->frame_ident);
        printf("\t\tFrag Offset:\t%u\n", (hdr->fragment_offset & 0b1111111111111) << 3);
        printf("\t\tFrag DF:\t%s\n", ((hdr->fragment_offset >> 13) & 0b010) ? "yes" : "no");
        printf("\t\tFrag MF:\t%s\n", ((hdr->fragment_offset >> 13) & 0b001) ? "yes" : "no");
        printf("\t\tIP CSum:\t%u\n", hdr->hdr_checksum);
        printf("\t\tType:\t0x%x\t", hdr->next_proto_id);
    }
    
    /* if the packet is from us, ignore it */
    if (interfaces[thread_interface_idx].ipv4_addr == *(uint32_t*)&hdr->src_addr) {
        if (debug) fprintf(stderr, "[*] Packet is from us. Ignoring...\n");
        return 0;
    }

    /* check if we have a route for this packet */
    int found = 0 ;
    pthread_mutex_lock(&rip_cache_mutex);
    for (int i = 0 ; i < (int)rip_cache_v4.size(); i++) {
        uint32_t dst_addr = *(uint32_t*)&hdr->dst_addr;

        /* if it's multicast, send it back to where it came from, which is the interface this thread is responsible for*/
        if (dst_addr == RIP_MULTICAST_ADDR) { 
            found = 1;
            reply_interface_idx = thread_interface_idx; 
            break;
        }

        /* find the interface we should write this packet to */
        if (rip_cache_v4[i].ip_dst == (dst_addr & rip_cache_v4[i].subnet_mask)) {
            if (rip_cache_v4[i].cost == RIP_COST_INFINITY) {
                continue;
            }
            reply_interface_idx = rip_cache_v4[i].iface_idx;
            found = 1;
        }
    }
    pthread_mutex_unlock(&rip_cache_mutex);

    if (!found) {
        fprintf(stderr, "[!] No route for ");
        print_addr_4((uint8_t*)&hdr->dst_addr);
        puts("");
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

    
    struct ipv4_hdr *reply_iph = NULL;
    int reply_iph_size;
    int ret; 
    switch (hdr->next_proto_id) {
        case IPV4_TYPE_TCP:
            printf("(TCP)\n");
            process_tcp((struct tcp_hdr *)(hdr + ipv4_hdr_len)); 
            break;
        case IPV4_TYPE_UDP:
            printf("(UDP)\n");
            ret = process_udp(in_packet + ipv4_hdr_len, (uint16_t*)hdr->src_addr, (uint16_t*)hdr->dst_addr, hdr->total_len - ipv4_hdr_len, iov_idx + 1); 
            if (ret <= 0) {
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
            if (is_reply_packet) {  /* only swap the src and dst addresses if we're replying back to the host */
                memcpy(&reply_iph->src_addr, hdr->dst_addr, 4);                          // Swap src and dst addresses
                memcpy(&reply_iph->dst_addr, hdr->src_addr, 4);
            }
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
            if (ret <= 0) {  
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