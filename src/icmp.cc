#include "icmp.h"


void print_icmp(struct icmp_hdr *hdr) {
    printf("\tICMP\tType:\t%u\n", hdr->type);
    printf("\t\tCode:\t%u\n", hdr->code);
    printf("\t\tCSum:\t%u\n", hdr->cksum);
    printf("\t\tIdent:\t%u", hdr->ident);
    printf("\t\tSeq Num:\t%u", hdr->seq_num);
}

/* return an integer indicating the length of the ICMP packet (including encapsulated packets).
 * This implementation is necessary in case the lower layer protocols (e.g. IPv4) need the ICMP packet size.
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.c`, included in `include.h`) is the index of the iov array to which the REPLY ICMP packet will be written. 
 */
int process_icmp(unsigned char *icmp_packet, int pkt_len, int iov_idx) {
    struct icmp_hdr *hdr = (struct icmp_hdr *)icmp_packet;
    //print_icmp(hdr);

    if (hdr->type == ICMP_TYPE_ECHO) {
        if (verify_cksum(hdr, sizeof(struct icmp_hdr))) {   // S + ~S === 0xFFFF
            fprintf(stderr, "[!] INVALID ICMP CHECKSUM.\n");
            return -1;
        }

        unsigned char *icmp_reply = (unsigned char*)malloc(pkt_len);
        struct icmp_hdr *reply_hdr = (struct icmp_hdr *)icmp_reply;
        if (!reply_hdr) {
            perror("process_icmp: ");
            return -1;
        }

        // everything mirrors the request, except for the message type
        reply_hdr->type = ICMP_TYPE_ECHO_REPLY;
        reply_hdr->code = 0;
        reply_hdr->cksum = 0;
        reply_hdr->ident = hdr->ident;              // copy from input packet as it's already in network byte order
        reply_hdr->seq_num = hdr->seq_num;
        
        // ICMP echo reply messsages MUST mirror the request's data as per RFC 792
        memcpy( (unsigned char*)icmp_reply + sizeof(struct icmp_hdr), 
                icmp_packet + sizeof(struct icmp_hdr), 
                pkt_len - sizeof(struct icmp_hdr));
        // checksum is computed over the entire packet
        reply_hdr->cksum = in_cksum((unsigned short*)reply_hdr, pkt_len, 0);   

        iov[iov_idx].iov_base = icmp_reply;
        iov[iov_idx].iov_len = pkt_len;
        iov_cnt++; 
        return pkt_len;

    } else if (hdr->type == ICMP_TYPE_ECHO_REPLY) {
        printf("Received ICMP reply: \n");
        //print_icmp(hdr);
    } else {
        printf("Sorry, we only support ICMP echo and echo replies right now :(");
    }
    return -1;
}

/* See RFC: https://datatracker.ietf.org/doc/html/rfc792 */
int iov_create_icmp_error(unsigned char *in_ipv4_pkt, int in_ipv4_len, int in_ipv4_hdr_len, uint8_t icmp_type, uint8_t icmp_code, int iov_idx) {
    unsigned char *icmp_pkt;
    int icmp_len = 0;
    uint32_t in_ipv4_src_addr = *(uint32_t*)( ((struct ipv4_hdr *)in_ipv4_pkt)->src_addr);

    /* if for some reason, we can't get back to the source, write it back to the interface we got this packet from */
    outgoing_interface_idx = get_interface_for_route(in_ipv4_src_addr);
    if (outgoing_interface_idx == -1) outgoing_interface_idx = thread_interface_idx; 


    switch (icmp_type) {
        case ICMP_TYPE_DEST_UNREACHABLE:
        {
            icmp_len  = sizeof(struct icmp_dest_unreachable_message_hdr) + in_ipv4_hdr_len + 8;
            icmp_pkt = (unsigned char*)malloc(icmp_len);
            struct icmp_dest_unreachable_message_hdr *icmp_hdr = (struct icmp_dest_unreachable_message_hdr *)icmp_pkt;
            if (!icmp_pkt) {
                perror("create_icmp_error: ");
                return - 1;
            }
            icmp_hdr->type = ICMP_TYPE_DEST_UNREACHABLE;
            icmp_hdr->code = icmp_code;
            icmp_hdr->unused = 0;
            memcpy(icmp_pkt + sizeof(struct icmp_dest_unreachable_message_hdr), in_ipv4_pkt, in_ipv4_hdr_len);
            memcpy(icmp_pkt + sizeof(struct icmp_dest_unreachable_message_hdr) + in_ipv4_hdr_len, in_ipv4_pkt + in_ipv4_hdr_len, 8);            icmp_hdr->cksum = 0;
            icmp_hdr->cksum = 0;
            icmp_hdr->cksum = in_cksum((uint16_t*)icmp_hdr, icmp_len, 0);
            break;
        }
        case ICMP_TYPE_TTL_EXPIRED:
        {
            icmp_len  = sizeof(struct icmp_ttl_expired_message_hdr) + in_ipv4_hdr_len + 8;
            icmp_pkt = (unsigned char*)malloc(icmp_len);
            struct icmp_ttl_expired_message_hdr *icmp_hdr = (struct icmp_ttl_expired_message_hdr *)icmp_pkt;
            if (!icmp_pkt) {
                perror("create_icmp_error: ");
                return - 1;
            }
            icmp_hdr->type = ICMP_TYPE_TTL_EXPIRED;
            icmp_hdr->code = icmp_code;
            icmp_hdr->unused = 0;
            memcpy(icmp_pkt + sizeof(struct icmp_ttl_expired_message_hdr), in_ipv4_pkt, in_ipv4_hdr_len);
            memcpy(icmp_pkt + sizeof(struct icmp_ttl_expired_message_hdr) + in_ipv4_hdr_len, in_ipv4_pkt + in_ipv4_hdr_len, 8);
            icmp_hdr->cksum = 0;
            icmp_hdr->cksum = in_cksum((uint16_t*)icmp_hdr, icmp_len, 0);
            break;            
        }
        default:
        {
            fprintf(stderr, "[!] Invalid ICMP type for error: %d\n", icmp_type);
            return -1;
        }
    }
    
    iov[iov_idx].iov_base = icmp_pkt;
    iov[iov_idx].iov_len = icmp_len;
    iov_cnt++;

    return icmp_len;
}

