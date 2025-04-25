#include "udp.h"
#include "rip.h"

void print_udp(struct udp_hdr *udp_datagram) {
    printf("\tUDP:\tSport:\t%u\n", ntohs(udp_datagram->src_port));
    printf("\t\tDport:\t%u\n", ntohs(udp_datagram->dst_port));
    printf("\t\tDGlen:\t%u\n", ntohs(udp_datagram->len));
    printf("\t\tCSum:\t%u\n", ntohs(udp_datagram->cksum));
}

/* get time since 00:00 Jan 1, 1900 */
uint32_t get_udp_time() {
    time_t now = time(NULL);
    return (uint32_t)(now + UNIX_TO_1900_EPOCH_OFFSET);    
}

uint16_t udp_cksum(uint16_t *udp_header, uint16_t *udp_data, uint16_t *ip_src, uint16_t *ip_dst, uint16_t udp_len) {
    uint32_t hdr_len = sizeof(struct udp_hdr);
    uint16_t ret;
    uint32_t sum = 0;
    // Add the pseudo-header
    sum += *(ip_src++);
    sum += *ip_src;
    sum = (sum >> 16) + (sum & 0xFFFF); // step 2
    
    sum += *(ip_dst++);
    sum += *ip_dst;

    sum = (sum >> 16) + (sum & 0xFFFF); // step 2
    
    sum += htons(IPPROTO_UDP);
    sum += htons(udp_len);

    sum = (sum >> 16) + (sum & 0xFFFF); // step 2
    while ((sum >> 16) > 0) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    // Now add the UDP headerhdr
    uint16_t *w = udp_header;
    while (hdr_len > 0) {
        sum += *w++;
        hdr_len -= 2;
    }
    while ((sum >> 16) > 0) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    /* Now add the UDP data */
    int rem = udp_len - sizeof(struct udp_hdr);
    w = udp_data;

    while (rem > 0) {
        sum += *w++;
        rem -= 2;
    }

    if (rem == 1) { // there might be an odd number of bytes in the UDP datagram
        sum += *w;
    }
    while ((sum >> 16) > 0) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }


    sum = (sum >> 16) + (sum & 0xFFFF); // step 2
    sum += (sum >> 16); // step 3
    ret = ~sum;         // ret is 16-bit, so we truncate sum to 16-bit here
    return ret;
}

/*
 * In the case of ICMP:
 * write the reply packet to iov[iov_idx]
 * where iov_idx (defined in `main.cc`, included in `include.h`) is the index of the iov array to which the REPLY ICMP packet will be written. 
 * In the case of RIP: 
 * write only the UDP header to iov[iov_idx], the data portion (the RIP packet) will be at iov[iov_idx + 1]
 * 
 * The IPv4 src_addr is passed as a pointer to the IPv4 address in network byte order so it's convenient calculate the UDP checksum.
 */
int process_udp(unsigned char *udp_datagram, uint16_t *src_addr, uint16_t *dst_addr, uint16_t udp_len, int iov_idx) {
    if (debug) {
        printf("[*] Received UDP datagram:\n");
        printf("\tUDP len:\t%u\n", udp_len);
    }
    print_udp((struct udp_hdr *)udp_datagram);

    /* UDP checksum is calculated from pseudo IPv4 header, UDP header, UDP data as per the RFC 862. 
     * To verify the received cksum, extract it, then set the field to 0 to calculate the checksum ourselves
     * then compare the calculated checksum with the original checksum.
     */
    uint16_t in_cksum = ((struct udp_hdr *)udp_datagram)->cksum; 
    ((struct udp_hdr *)udp_datagram)->cksum = 0;
    uint16_t our_cksum = udp_cksum((uint16_t*)udp_datagram, (uint16_t*)(udp_datagram + sizeof(struct udp_hdr)), src_addr, dst_addr, udp_len);
     if (in_cksum != our_cksum) {      // should add to 0 as we already added the original checksum. S + ~S === 0
        fprintf(stderr, "[!] INVALID UDP CHECKSUM. Received: %u, but computed: %u\n", in_cksum, our_cksum);
        return -1;
     }    
    
    struct udp_hdr *hdr = (struct udp_hdr *)udp_datagram;
    int ret = -1;
    switch (ntohs(hdr->dst_port)) {
        case UDP_PORT_ECHO: // echo
        {
            hdr->cksum = 0;
            hdr->len = htons(udp_len);
            hdr->dst_port = hdr->src_port;
            hdr->src_port = htons(UDP_PORT_ECHO);
            hdr->cksum = udp_cksum((uint16_t*)hdr, (uint16_t*)(udp_datagram + sizeof(struct udp_hdr)), src_addr, dst_addr, udp_len);

            iov[iov_idx].iov_base = (unsigned char*)malloc(udp_len);
            memcpy(iov[iov_idx].iov_base, udp_datagram, udp_len);   // copy the data in the request, as per the RFC 862
            iov[iov_idx].iov_len = udp_len;
            iov_cnt++;
            return udp_len;
        }
        case UDP_PORT_TIME: // time protocol
        {
            int reply_len = sizeof(struct udp_hdr) + 4;
            unsigned char *reply = (unsigned char*)malloc(reply_len); // 4 bytes for the time in the data
            struct udp_hdr *reply_hdr = (struct udp_hdr *)reply;
            reply_hdr->cksum = 0;
            reply_hdr->len = htons(reply_len);
            reply_hdr->dst_port = hdr->src_port;
            reply_hdr->src_port = htons(UDP_PORT_TIME);
            
            uint32_t *data = (uint32_t*)(reply + sizeof(struct udp_hdr));
            *data = htonl(get_udp_time());
            reply_hdr->cksum = udp_cksum((uint16_t*)reply_hdr, (uint16_t*)(data), src_addr, dst_addr, reply_len);

            iov[iov_idx].iov_base = reply;
            iov[iov_idx].iov_len = reply_len;
            iov_cnt++;
            return reply_len;
        }

        case UDP_PORT_RIP: // RIP
        {
            ret = process_rip(udp_datagram + sizeof(struct udp_hdr), *(uint32_t *)src_addr, udp_len - sizeof(struct udp_hdr), iov_idx + 1);
            if (ret <= 0) {
                return ret;
            }
            uint16_t reply_len = sizeof(struct udp_hdr) + ret;
            unsigned char *reply = (unsigned char*)malloc(reply_len); // 4 bytes for the time in the data
            struct udp_hdr *reply_hdr = (struct udp_hdr *)reply;
            reply_hdr->cksum = 0;
            reply_hdr->len = htons(reply_len);
            reply_hdr->dst_port = hdr->src_port;
            reply_hdr->src_port = htons(UDP_PORT_RIP);
            
            reply_hdr->cksum = udp_cksum((uint16_t*)reply_hdr, (uint16_t*)iov[iov_idx+1].iov_base, src_addr, dst_addr, reply_len);

            iov[iov_idx].iov_base = reply;
            iov[iov_idx].iov_len = reply_len;
            iov_cnt++;
            return reply_len;
        }
           
        default:
            fprintf(stderr, "[!] Received port %d... Only support UDP echo at this time...\n", ntohs(hdr->dst_port));
            return -1;
    }
    return ret;
}



