#include "rip.h"

std::map<uint32_t, struct rip_entry> rip_cache_v4;

/* print RIP header */
void print_rip(struct rip_hdr *hdr) {
    printf("\tRIP:\tCommand:\t%s\n", (hdr->command == 1) ? "Request" : "Reply");
    printf("\t\tVersion:\t%u\n", hdr->version);
    printf("\t\tAddr Family:\t%u\n", ntohs(hdr->addr_family));
    printf("\t\tZero 1:\t%u\n", ntohs(hdr->zero));
    printf("\t\tZero 2:\t%u\n", ntohs(hdr->zero2));
}

int process_rip(unsigned char *rip_packet, uint32_t ipv4_src_addr, int pkt_len, int iov_idx) {
    struct rip_hdr *hdr = (struct rip_hdr *)rip_packet;

    if (hdr->version == 0) {
        fprintf(stderr, "[!] INVALID RIP VERSION: %d\n", hdr->version);
        return -1;
    }

    /* As per the RFC, make sure it is from one of our interfaces */
    int from_interface_idx = -1;
    for (int i = 0 ; i < num_interfaces; i++) {
        if (interfaces[i].ipv4_addr == ipv4_src_addr) {
            from_interface_idx = i;
            break;
        }
    }
    if (from_interface_idx == -1) {
        fprintf(stderr, "[!] RIP packet is not from one of our interfaces. Ignoring...\n");
        return 0;
    }

    if (hdr->command == 1) {    // RIP request
        if (debug) print_rip(hdr);
    
        // construct a RIP reply packet
        unsigned char *rip_reply = (unsigned char*)malloc(pkt_len);
        struct rip_hdr *reply_hdr = (struct rip_hdr *)rip_reply;
        if (!reply_hdr) {
            perror("process_rip: ");
            return -1;
        }

        reply_hdr->command = 2;    // RIP reply
        reply_hdr->version = hdr->version;
        reply_hdr->addr_family = hdr->addr_family;
        reply_hdr->zero2 = 0;

        iov[iov_idx].iov_base = rip_reply;
        iov[iov_idx].iov_len = pkt_len;
        iov_cnt++;
        return pkt_len;

    } else if (hdr->command == 2) {     // RIP Response/Reply
        if (debug) print_rip(hdr);

        
    }

    return -1;
}
