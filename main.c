#include "include.h"
#include "icmp.h"
#include "ipv4.h"
#include "utils.h"
/* this normally comes from the pcap.h header file, but we'll just be using
 * a few specific pieces, so we'll add them here
 *
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 */

/* every pcap file starts with this structure */
struct pcap_file_header {
	bpf_u_int32 magic;
	unsigned short version_major;
	unsigned short version_minor;
	bpf_int32 thiszone;	/* gmt to local correction; this is always 0 */
	bpf_u_int32 sigfigs;	/* accuracy of timestamps; this is always 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

/*
 * Generic per-packet information, as supplied by libpcap.
 * this is the second record in the file, and every packet starts
 * with this structure (followed by the packet date bytes)
 */
struct pcap_pkthdr {
	bpf_u_int32 ts_secs;		/* time stamp */
	bpf_u_int32 ts_usecs;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length of this packet (off wire) */
};

struct eth_hdr {
    uint8_t  h_dest[6];   /* destination eth addr */
    uint8_t  h_source[6]; /* source ether addr    */
    uint16_t h_proto;            /* packet type ID field */
};
// https://en.wikipedia.org/wiki/Address_Resolution_Protocol
struct arp_ipv4_hdr {
    uint8_t     h_type[2];
    uint8_t     p_type[2];
    uint8_t     hlen_plen[2];
    uint8_t     op[2];
    uint8_t     sha[6];
    uint8_t     spa[4];
    uint8_t     tha[6];
    uint8_t     tpa[4];
};

char tcp_flag_string[] = "FSRPAU"; 
uint32_t host_ipv4_addr;
int debug = 0;
int resolveDNS = 1;
int reverseEndian = 0;

// since we're reading & writing to the same file, we need 2 different FDs 
// so that the write one can have O_APPEND that will always seek to the EOF to write so we don't overwrite incoming packets
int pcap_fd_read;
int pcap_fd_write;
struct pcap_file_header pfh;


void print_ethernet(struct eth_hdr *peh) {
    unsigned char *c = (unsigned char*)&(peh->h_proto);
	printf("%02x:%02x:%02x:%02x:%02x:%02x	%02x:%02x:%02x:%02x:%02x:%02x	0x%02x%02x\n", 
        peh->h_dest[0], peh->h_dest[1], peh->h_dest[2],
        peh->h_dest[3], peh->h_dest[4], peh->h_dest[5],
        peh->h_source[0], peh->h_source[1], peh->h_source[2],
        peh->h_source[3], peh->h_source[4], peh->h_source[5], c[0], c[1]);
}

void print_arp(struct arp_ipv4_hdr *arp_frame) {
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
}

/* write pcap header + `len` bytes from `data` to the packet capture file `pcap_fd` */
void write_pcap(void *data, bpf_u_int32 len) {
    struct pcap_pkthdr *pcap_hdr = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    // write the pcap header
    struct timeval tv;
    int ret = gettimeofday(&tv, NULL);
    if (ret == -1) {
        perror("gettimeofday");
        return;
    }

    pcap_hdr->ts_secs = tv.tv_sec;
    pcap_hdr->ts_usecs = tv.tv_usec;
    pcap_hdr->caplen = len;
    pcap_hdr->len = len;

    // write the pcap header first
    ret = write(pcap_fd_write, pcap_hdr, sizeof(struct pcap_pkthdr));
    if (ret != sizeof(struct pcap_pkthdr)) {
        perror("write");
        return;
    }
    // move the read pointer to after this header 
    lseek(pcap_fd_read, ret, SEEK_CUR);

    // then write the packet
    ret = write(pcap_fd_write, (unsigned char *)data, len);
    if (ret != len) {
        perror("write");
        return;
    }
    // move the read pointer to after this packet 
    lseek(pcap_fd_read, ret, SEEK_CUR);
    free(pcap_hdr);
}

/* open .dmp pcap file (2 separate fds for read and write) and verify its header */
void setup(char *filename) {
    // get pcap filename in the form X.X.X.0_masklength first, then open pcap it
    int l = strlen(filename);
    char *_filename = (char*)malloc(l + 6);
    if (get_ip_and_filename(filename, _filename, &host_ipv4_addr) != 0) {
        exit(123);
    }
    pcap_fd_read = open(_filename, O_RDONLY);
    pcap_fd_write = open(_filename, O_WRONLY | O_APPEND);
    if (pcap_fd_read < 0 || pcap_fd_write < 0) {
        perror(_filename);
        exit(1);
    }

    /* read the pcap_file_header at the beginning of the file, check it, then print as requested */
    int ret = read(pcap_fd_read, &pfh, sizeof(pfh));
    if (ret <= 0) {
        perror("read");
        exit(1);
    }
    if (ret < (int)sizeof(pfh)) {
        printf("truncated pcap header: only %d bytes\n", ret);
        exit(1);
    }
    if (pfh.magic == PCAP_MAGIC_LITTLE) { // packet is in little-endian
        reverseEndian = 0;
    } else if (pfh.magic == PCAP_MAGIC_BIG) {
        reverseEndian = 1;
    } else {
        fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
        exit(1);
    }

    // reverse the bytes if the packet was originally in big-endian
    if (reverseEndian) {
        reverse_assign(&pfh.version_major, sizeof(pfh.version_major));
        reverse_assign(&pfh.version_minor, sizeof(pfh.version_minor));
        reverse_assign(&pfh.linktype, sizeof(pfh.linktype));
    }

    if (pfh.version_major != PCAP_VERSION_MAJOR || pfh.version_minor != PCAP_VERSION_MINOR) {
        fprintf(stderr, "invalid pcap version: %d.%d\n", pfh.version_major, pfh.version_minor);
        exit(1);
    }

    printf("header magic: %x\n", PCAP_MAGIC_LITTLE);
    printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
    printf("header linktype: %d\n\n", pfh.linktype);
}

void loop() {
    char* in_packet = (char*)malloc(2 << 20);
	/* now read each packet in the file */
	while (1) {

		/* read the pcap_packet_header, then print as requested */
        struct pcap_pkthdr pph;
        int ret = read(pcap_fd_read, &pph, sizeof(pph));
        if (ret < 0) {
            perror("read");
            exit(1);
        } else if (ret == 0) continue;    // EOF
        else if (ret < (int)sizeof(pph)) {
            printf("truncated packet header: only %d bytes\n", ret);
            exit(1);
        }

        if (reverseEndian) {
            reverse_assign(&pph.caplen, sizeof(pph.caplen));
            reverse_assign(&pph.ts_secs, sizeof(pph.ts_secs));
            reverse_assign(&pph.ts_usecs, sizeof(pph.ts_usecs));
        }

        // now read the actual packet
        ret = read(pcap_fd_read, in_packet, pph.caplen);        
        if (ret < 0) {
            perror("read");
            exit(1);
        } else if (ret == 0) break;    // EOF
        else if (ret < (int)pph.caplen) {
            printf("truncated packet: only %d bytes\n", ret);
            exit(1);
        }
        in_packet[ret] = '\0';
        if (reverseEndian) {
            reverse_assign(&pph.ts_secs, sizeof(pph.ts_secs));
            reverse_assign(&pph.ts_usecs, sizeof(pph.ts_usecs));
            reverse_assign(&pph.len, sizeof(pph.len));
        }

         // some format printing stuffs
        char *tmp = (char*)malloc(30);
        if (!tmp) {
            perror("malloc:");
            exit(123);
        }
        long double f = pph.ts_secs;
        f += (pph.ts_usecs / 1000000.0);
        ret = sprintf(tmp, "%.9Lf", f);
        tmp[ret] = '\0';
		printf("%20s\t%d\t%d\t", tmp, pph.caplen, pph.len);
        free(tmp);

        if (pfh.linktype == 1) { 
		    print_ethernet((struct eth_hdr *) in_packet);
            
            int data_len = 0;
            unsigned char *data = NULL;
            struct eth_hdr *orig_eth = (struct eth_hdr *)in_packet;
            orig_eth->h_proto = htons(orig_eth->h_proto);

            switch (orig_eth->h_proto) { 
                case ETHERTYPE_IPV4: // IPv4 
                    data = process_ipv4((struct ipv4_hdr *)(in_packet + sizeof(struct eth_hdr)), &data_len);
                    if (data == NULL) {
                        fprintf(stderr, "process_ipv4 failed.\n");
                        break;
                    }
                    int frame_len = sizeof(struct eth_hdr) + data_len;

                    // Allocate buffer for the full Ethernet frame
                    unsigned char *full_frame = (unsigned char *)malloc(frame_len);
                    if (!full_frame) {
                        perror("malloc full_frame");
                        exit(1);
                    }

                    // Copy Ethernet header from original packet and swap MAC addresses
                    struct eth_hdr *new_eth = (struct eth_hdr *)full_frame;
                    memcpy(new_eth->h_dest, orig_eth->h_source, 6);   
                    memcpy(new_eth->h_source, orig_eth->h_dest, 6);    
                    new_eth->h_proto = htons(ETHERTYPE_IPV4);    

                    // Copy the IP packet
                    memcpy(full_frame + sizeof(struct eth_hdr), data, data_len);
                    free(data);
                    write_pcap(full_frame, frame_len);    // have to ntohs as we already wrote the total len in network byte order
                    free(full_frame);
                    break;
                case ETHERTYPE_ARP:
                    print_arp((struct arp_ipv4_hdr *)(in_packet + sizeof(struct eth_hdr)));
                    break;
                default:
                    break;
            }
        }
	}
}

/* 
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */
int main(int argc, char *argv[])    
{
	char *filename;

	if (argc == 2) {
		filename = argv[1];
	} else if ((argc == 3) && (strcmp(argv[1],"-i") == 0)) {
		resolveDNS = 0;
		filename = argv[2];
	} else {
		fprintf(stdout,"Usage: %s [-i] IPv4addr_masklength\n", argv[0]);
		exit(99);
	}
	setup(filename);
    loop();
}

