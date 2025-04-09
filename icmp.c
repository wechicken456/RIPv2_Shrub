#include "icmp.h"


void print_icmp(struct icmp_hdr *icmp_packet) {
    printf("\tICMP\tType:\t%u\n", icmp_packet->type);
    printf("\t\tCode:\t%u\n", icmp_packet->code);
    printf("\t\tCSum:\t%u\n", icmp_packet->cksum);
    printf("\t\tIdent:\t%u", icmp_packet->ident);
    printf("\t\tSeq Num:\t%u", icmp_packet->seq_num);
}

unsigned char* process_icmp(struct icmp_hdr *icmp_packet, int pkt_len, int *reply_pkt_size) {
    print_icmp(icmp_packet);

    // write replyonse to pcap file. 
    if (icmp_packet->type == ICMP_TYPE_ECHO) {
        if (verify_cksum(icmp_packet, sizeof(struct icmp_hdr))) {   // S + ~S === 0xFFFF
            fprintf(stderr, "[!] INVALID ICMP CHECKSUM.\n");
            return NULL;
        }

        unsigned char *icmp_reply = (unsigned char*)malloc(pkt_len);
        struct icmp_hdr *reply_hdr = (struct icmp_hdr *)icmp_reply;
        if (!reply_hdr) {
            perror("process_icmp: ");
            return NULL;
        }

        // everything mirrors the request, except for the message type
        reply_hdr->type = ICMP_TYPE_ECHO_REPLY;
        reply_hdr->code = 0;
        reply_hdr->cksum = 0;
        reply_hdr->ident = icmp_packet->ident;              // copy from input packet as it's already in network byte order
        reply_hdr->seq_num = icmp_packet->seq_num;
        
        // ICMP echo reply messsages MUST mirror the request's data as per RFC 792
        memcpy( (unsigned char*)icmp_reply + sizeof(struct icmp_hdr), 
                (unsigned char*)icmp_packet + sizeof(struct icmp_hdr), 
                pkt_len - sizeof(struct icmp_hdr));
        // checksum is computed over the entire packet
        reply_hdr->cksum = in_cksum((unsigned short*)reply_hdr, pkt_len, 0);   

        *reply_pkt_size = pkt_len;
        return icmp_reply;

    } else if (icmp_packet->type == ICMP_TYPE_ECHO_REPLY) {
        printf("Received ICMP reply: \n");
        print_icmp(icmp_packet);
    } else {
        printf("Sorry, we only support ICMP echo and echo replyonses right now :(");
    }
    return NULL;
}
