#include "ipv4.h"
#include "tcp.h"
#include "udp.h"
#include "rip.h"
#include "icmp.h"
#include "ethernet.h"
#include "include.h"

int ipv4_reply_proto = 0; /* check ipv4.h for a description */

int iov_create_ipv4_hdr(int32_t src_addr, uint32_t dst_addr, int data_len, int proto_id, int iov_idx) {
    // allocate buffer for the IPv4 header. 
    struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)malloc(sizeof(struct ipv4_hdr));
    if (!ipv4_hdr) {
        perror("iov_create_ipv4_hdr: ");
        return -1;
    }
    ipv4_hdr->version_ihl = 0x45;                                              
    ipv4_hdr->type_of_service = 0;                      
    ipv4_hdr->total_len = htons(sizeof(struct ipv4_hdr) + data_len);       // Total length = IPv4 header + ICMP packet   
    ipv4_hdr->frame_ident = 0x4141;
    ipv4_hdr->fragment_offset = 0;                                       
    ipv4_hdr->time_to_live = 64;                                              // random TTL 
    ipv4_hdr->next_proto_id = proto_id;                                

    memcpy(ipv4_hdr->src_addr, &src_addr, 4); 
    memcpy(ipv4_hdr->dst_addr, &dst_addr, 4);
    ipv4_hdr->hdr_checksum = 0;                                            // checksum is set to 0 before calculating it
    ipv4_hdr->hdr_checksum = in_cksum((unsigned short *)ipv4_hdr, sizeof(struct ipv4_hdr), 0);
    iov[iov_idx].iov_base = ipv4_hdr;
    iov[iov_idx].iov_len = sizeof(struct ipv4_hdr);
    iov_cnt++;
    return sizeof(struct ipv4_hdr);
}

int find_interface_for_nxt_hop_idx(int nxt_hop) {
    int ret_interface_idx = -1;
    for (int i = 0 ; i < num_interfaces; i++) {
        if (i == default_route_idx) continue;
        if ( (nxt_hop & interfaces[i].subnet_mask) == (interfaces[i].ipv4_addr & interfaces[i].subnet_mask) ) { 
            ret_interface_idx = i;
            break;
        }
    }
    return ret_interface_idx;
}

int get_interface_for_route(uint32_t dst_addr) {
    int nxt_hop_idx = -1, ret_interface_idx = -1;
    pthread_mutex_lock(&rip_cache_mutex);
    for (int i = 0 ; i < (int)rip_cache_v4.size(); i++) {

        if ( i == default_route_idx) continue;

        /* if it's multicast, we don't have to reply. But if we do, 
        * send it back to where it came from, which is the interface this thread is responsible for
        */
        if (dst_addr == RIP_MULTICAST_ADDR) { 
            pthread_mutex_unlock(&rip_cache_mutex);
            return thread_interface_idx;
        }

        /* find the interface we should forward this packet to */
        if (rip_cache_v4[i].ip_dst == (dst_addr & rip_cache_v4[i].subnet_mask)) {
            if (rip_cache_v4[i].cost == RIP_COST_INFINITY) {
                continue;
            }
            nxt_hop_idx = i;
            break;
        }
    }

    if (nxt_hop_idx != -1) {
        /* find the interface that is responsible for the next hop 
         * this could fail, so there's another check below
         */
        uint32_t nxt_hop = rip_cache_v4[nxt_hop_idx].next_hop;
        ret_interface_idx = find_interface_for_nxt_hop_idx(nxt_hop);
    }

    if (default_route_idx != -1 && ret_interface_idx < 0) {
        /* if we don't have a route for this packet, but we have a default route, use it 
         * If the default route is directly connected, then we have an interface for it 
         * Otherwise, another router advertised it, so we have to write the packet to the interface that received the advertisement
         */
        if (rip_cache_v4[default_route_idx].is_directly_connected) {
            pthread_mutex_unlock(&rip_cache_mutex);
            return default_route_idx;
        }

        /* if the default route is not directly connected, 
         * then we have to find the interface that is responsible  
         */
        nxt_hop_idx = default_route_idx;
        uint32_t nxt_hop = rip_cache_v4[nxt_hop_idx].next_hop;
        ret_interface_idx = find_interface_for_nxt_hop_idx(nxt_hop);
        if (ret_interface_idx < 0) ret_interface_idx = rip_cache_v4[nxt_hop_idx].iface_idx;
    }
    pthread_mutex_unlock(&rip_cache_mutex);
    return ret_interface_idx;
}

/* return an integer indicating the logical (if all the encapsulated packets were contiguous)
 * length of the IPv4 packet (including outgoing_interface_idxencapsulated packets): <0 for error, 0 if not for us (the interface this thread is responsible for reading from), 
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
    for (int i = 0 ;  i < num_interfaces; i++) {
        if (interfaces[i].ipv4_addr == *(uint32_t*)&(hdr->src_addr)) {
            if (debug) fprintf(stderr, "[*] process_ipv4: Packet is from us. Ignoring...\n");
            return 0;
        }
    }
   
    // printf("interfaces[thread_interface_idx].ipv4_addr = %u\n", interfaces[thread_interface_idx].ipv4_addr);
    // printf("hdr->dst_addr = %u\n", *(uint32_t*)&(hdr->dst_addr));
    /* check if the packet is for us */
    outgoing_interface_idx = thread_interface_idx;
    meant_for_interface_idx = thread_interface_idx;
    if (*(uint32_t*)&(hdr->dst_addr) == RIP_MULTICAST_ADDR
        || *(uint32_t*)&(hdr->dst_addr) == 0xFFFFFFFF) {
        meant_for_interface_idx = thread_interface_idx;
        is_for_us = 1;
    } else {
        for (int i = 0 ; i < num_interfaces; i++) {
            if (interfaces[i].ipv4_addr == *(uint32_t*)&(hdr->dst_addr)) {
                meant_for_interface_idx = i;
                outgoing_interface_idx = i;
                is_for_us = 1;
                break;
                /* UDP header */
            } else {
                is_for_us = 0;
            }
        }
    }



    /* forward if it's not for us */
    if (!is_for_us) {
        int found_interface_idx = get_interface_for_route(*(uint32_t*)&(hdr->dst_addr));
        if (found_interface_idx == -1) {
            fprintf(stderr, "[!] NOT for us: No route for ");
            print_addr_4((uint8_t*)&hdr->dst_addr);
            puts("\nSending ICMP error message..."); 
            int icmp_len = iov_create_icmp_error(in_packet, ntohs(hdr->total_len), ipv4_hdr_len, ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NO_ROUTE, iov_idx + 1);
            int ipv4_hdr_len = iov_create_ipv4_hdr(interfaces[outgoing_interface_idx].ipv4_addr, *(uint32_t*)&(hdr->src_addr), icmp_len, IPPROTO_ICMP, iov_idx);
            if (icmp_len <= 0 || ipv4_hdr_len <= 0) {
                fprintf(stderr, "[!] Failed to create ICMP error packet for interface %d...!!!\n", outgoing_interface_idx);
                return -1;
            }
            return icmp_len + ipv4_hdr_len;
        }
        outgoing_interface_idx = found_interface_idx;
                
        /* If found a route to forward this packet, use it
         * we have to create a new packet and copy from it instead of using the original one 
         * because the original packet is a global buffer to read from pcap,
         * while write_pcap will free the buffers in the iov array. So we can't free the global buffer.
         */
        fprintf(stderr, "[!] Packet is not for us, but we have a route for it. Forwarding...\n");
        if (hdr->time_to_live == 1) {
            fprintf(stderr, "[!] TTL expired for ");
            print_addr_4((uint8_t*)&hdr->dst_addr);
            puts("");
            int icmp_len = iov_create_icmp_error(in_packet, ntohs(hdr->total_len), ipv4_hdr_len, ICMP_TYPE_TTL_EXPIRED, ICMP_CODE_TTL_EXPIRED, iov_idx + 1);
            int ipv4_hdr_len = iov_create_ipv4_hdr(interfaces[outgoing_interface_idx].ipv4_addr, *(uint32_t*)&(hdr->src_addr), icmp_len, IPPROTO_ICMP, iov_idx);
            if (icmp_len <= 0 || ipv4_hdr_len <= 0) {
                fprintf(stderr, "[!] Failed to create ICMP error packet for interface %d...!!!\n", outgoing_interface_idx);
                return -1;
            }
            return icmp_len + ipv4_hdr_len;
        }
        hdr->time_to_live = ntohs(htons(hdr->time_to_live) - 1);
        hdr->hdr_checksum = 0;
        hdr->hdr_checksum = in_cksum((unsigned short *)hdr, ipv4_hdr_len, 0);

        int total_len = ntohs(hdr->total_len);
        unsigned char *ipv4_reply = (unsigned char*)malloc(total_len);
        memcpy(ipv4_reply, in_packet, total_len);
        iov[iov_idx].iov_base = ipv4_reply;
        iov[iov_idx].iov_len = total_len;
        iov_cnt++;
        return hdr->total_len;
    }

    /* it is meant for us, so find a route to send it back */
    int found_interface_idx = get_interface_for_route(*(uint32_t*)&(hdr->src_addr));
    if (found_interface_idx == -1) {
        fprintf(stderr, "[!] For us: but can't find route to reply to...");
        print_addr_4((uint8_t*)&hdr->src_addr);
        puts("\nSending ICMP error message..."); 
        int icmp_len = iov_create_icmp_error(in_packet, ntohs(hdr->total_len), ipv4_hdr_len, ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NO_ROUTE, iov_idx + 1);
        int ipv4_hdr_len = iov_create_ipv4_hdr(interfaces[outgoing_interface_idx].ipv4_addr, *(uint32_t*)&(hdr->src_addr), icmp_len, IPPROTO_ICMP, iov_idx);
        if (icmp_len <= 0 || ipv4_hdr_len <= 0) {
            fprintf(stderr, "[!] Failed to create ICMP error packet for interface %d...!!!\n", outgoing_interface_idx);
            return -1;
        }
        return icmp_len + ipv4_hdr_len;
    }
    outgoing_interface_idx = found_interface_idx;

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
            ipv4_reply_proto = IPPROTO_TCP;
            printf("(TCP)\n");
            process_tcp((struct tcp_hdr *)(hdr + ipv4_hdr_len)); 
            break;
        case IPV4_TYPE_UDP:
            ipv4_reply_proto = IPPROTO_UDP;
            printf("(UDP)\n");
            ret = process_udp(in_packet, hdr->total_len, ipv4_hdr_len, (uint16_t*)hdr->src_addr, (uint16_t*)hdr->dst_addr, hdr->total_len - ipv4_hdr_len, iov_idx + 1); 
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
            reply_iph->next_proto_id = ipv4_reply_proto;                                    // UDP 

             /* only change the src and dst addresses if we're replying back to the host. Otherwise copy the same addresses and forward the packet */
            if (is_for_us) {  
                memcpy(reply_iph->src_addr, &interfaces[meant_for_interface_idx].ipv4_addr, 4); 
                memcpy(reply_iph->dst_addr, hdr->src_addr, 4);
            } else {
                memcpy(reply_iph->src_addr, hdr->src_addr, 4);
                memcpy(reply_iph->dst_addr, hdr->dst_addr, 4);
            }
            // checksum is computed over ONLY the header as per RFC 791
            reply_iph->hdr_checksum = in_cksum((unsigned short *)reply_iph, sizeof(*reply_iph), 0);
            
            iov[iov_idx].iov_base = (unsigned char*)reply_iph;
            iov[iov_idx].iov_len = reply_iph_size;     
            iov_cnt++; 
            return reply_iph_size;

        case IPV4_TYPE_ICMP:
            ipv4_reply_proto = IPPROTO_ICMP;
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
            
            /* only change the src and dst addresses if we're replying back to the host */
             if (is_for_us) {  
                memcpy(reply_iph->src_addr, &interfaces[meant_for_interface_idx].ipv4_addr, 4); 
                memcpy(reply_iph->dst_addr, hdr->src_addr, 4);
            } else {
                memcpy(reply_iph->src_addr, hdr->src_addr, 4);
                memcpy(reply_iph->dst_addr, hdr->dst_addr, 4);
            }

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